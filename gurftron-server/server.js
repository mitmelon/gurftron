import Fastify from 'fastify';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import { Account, Contract, RpcProvider, CallData, hash } from 'starknet';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load .env from root directory
dotenv.config({ path: path.resolve(__dirname, '../.env') });

const fastify = Fastify({ logger: true });

// ==================== DATABASE SETUP ====================
await mongoose.connect(process.env.MONGODB_URI);

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', () => fastify.log.info('Connected to MongoDB'));

// ==================== SCHEMAS ====================
const requestSchema = new mongoose.Schema({
  walletAddress: String,
  methodName: String,
  arguments: mongoose.Schema.Types.Mixed,
  transactionHash: String,
  status: { type: String, enum: ['pending', 'success', 'failed'], default: 'pending' },
  error: String,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

const eventSchema = new mongoose.Schema({
  transactionHash: String,
  eventName: String,
  eventData: mongoose.Schema.Types.Mixed,
  blockNumber: Number,
  indexed: mongoose.Schema.Types.Mixed,
  parsed: mongoose.Schema.Types.Mixed,
  createdAt: { type: Date, default: Date.now },
});

const Request = mongoose.model('Request', requestSchema);
const ContractEvent = mongoose.model('ContractEvent', eventSchema);

// ==================== MIDDLEWARE ====================
const authenticateAPIKey = async (request, reply) => {
  // Skip auth for health check
  if (request.url === '/health') {
    return;
  }

  const authHeader = request.headers.authorization;
  fastify.log.info(`Auth header: ${authHeader}`);
  fastify.log.info(`Expected API Key: ${process.env.API_KEY}`);

  if (!authHeader) {
    fastify.log.error('Missing authorization header');
    return reply.status(401).send({ 
      error: 'Missing authorization header',
      message: 'Please provide Authorization: Bearer YOUR_API_KEY'
    });
  }

  if (!authHeader.startsWith('Bearer ')) {
    fastify.log.error('Invalid authorization format');
    return reply.status(401).send({ 
      error: 'Invalid authorization format',
      message: 'Use: Authorization: Bearer YOUR_API_KEY'
    });
  }

  const apiKey = authHeader.substring(7).trim();

  if (!process.env.API_KEY) {
    fastify.log.error('API_KEY not set in environment variables');
    return reply.status(500).send({ error: 'Server configuration error: API_KEY not set' });
  }

  if (apiKey !== process.env.API_KEY) {
    fastify.log.error(`Invalid API key provided. Got: ${apiKey}, Expected: ${process.env.API_KEY}`);
    return reply.status(403).send({ error: 'Invalid API key' });
  }

  fastify.log.info('Authorization successful');
};

fastify.addHook('preHandler', authenticateAPIKey);

// ==================== STARKNET SETUP ====================
const provider = new RpcProvider({ nodeUrl: process.env.STARKNET_RPC_URL });

const account = new Account(
  provider,
  process.env.WALLET_ADDRESS,
  process.env.WALLET_PRIVATE_KEY
);

// ==================== EVENT MONITORING ====================
const eventNames = {
  DocumentInsertedEvent: 'DocumentInserted',
  DocumentUpdatedEvent: 'DocumentUpdated',
  DocumentDeletedEvent: 'DocumentDeleted',
  DocumentApprovedEvent: 'DocumentApproved',
  DocumentRejectedEvent: 'DocumentRejected',
  DocumentVoteSubmitted: 'DocumentVoteSubmitted',
  WhitelistVoteSubmitted: 'WhitelistVoteSubmitted',
  DocumentWhitelistApproved: 'DocumentWhitelistApproved',
  PointsAwardedForApproval: 'PointsAwardedForApproval',
  PointsAwardedForVoting: 'PointsAwardedForVoting',
  BadgeEarnedEvent: 'BadgeEarned',
  RewardClaimedEvent: 'RewardClaimed',
  UserRegisteredEvent: 'UserRegistered',
  UserBannedEvent: 'UserBanned',
  UserUnbannedEvent: 'UserUnbanned',
  StakeDepositedEvent: 'StakeDeposited',
  StakeWithdrawnEvent: 'StakeWithdrawn',
  StakeSlashedEvent: 'StakeSlashed',
  CollectionCreatedEvent: 'CollectionCreated',
  MaliciousDataReported: 'MaliciousDataReported',
};

const eventSelectors = {};
for (const [eventNameKey, readableName] of Object.entries(eventNames)) {
  eventSelectors[hash.getSelectorFromName(eventNameKey)] = readableName;
}

const parseEventData = (event) => {
  const eventData = {};
  const indexed = {};

  if (event.keys && event.keys.length > 0) {
    indexed.keys = event.keys;
  }

  if (event.data && event.data.length > 0) {
    eventData.rawData = event.data;
    eventData.data = event.data.map(d => {
      try {
        // Attempt hex -> integer conversion when possible
        if (typeof d === 'string' && d.startsWith('0x')) return parseInt(d, 16);
        return d;
      } catch {
        return d;
      }
    });
  }

  return { eventData, indexed };
};

const storeEvent = async (transactionHash, eventName, eventData, indexed, blockNumber = 0, parsed = {}) => {
  try {
    const contractEvent = new ContractEvent({
      transactionHash,
      eventName,
      eventData,
      indexed,
      parsed,
      blockNumber,
    });
    await contractEvent.save();
    fastify.log.info(`Event stored: ${eventName} from tx ${transactionHash}`);
  } catch (error) {
    fastify.log.error(`Error storing event: ${error.message}`);
  }
};

const fetchTransactionEvents = async (transactionHash) => {
  try {
    fastify.log.info(`Fetching events for transaction: ${transactionHash}`);
    const receipt = await provider.getTransactionReceipt(transactionHash);

    if (!receipt || !receipt.events) {
      fastify.log.info(`No events found for transaction: ${transactionHash}`);
      return [];
    }

    const storedEvents = [];

    for (const event of receipt.events) {
      const { eventData, indexed } = parseEventData(event);
      
      let eventName = 'UnknownEvent';
      if (event.keys && event.keys[0]) {
        const selector = event.keys[0];
        eventName = eventSelectors[selector] || 'UnknownEvent';
      }

      // Build parsed object with common fields when possible
      const parsed = {};
      try {
        const keys = indexed.keys || [];
        // helper to read data values safely
        const data = eventData.data || [];

        // Map common events to structured parsed fields
        switch (eventName) {
          case 'DocumentInserted':
            parsed.caller = keys[0] ? String(keys[0]) : undefined;
            parsed.collection = keys[1] ? String(keys[1]) : undefined;
            parsed.document_id = keys[2] ? String(keys[2]) : undefined;
            parsed.data_hash = data[0] !== undefined ? String(data[0]) : undefined;
            parsed.timestamp = data[1] || undefined;
            break;
          case 'DocumentUpdated':
            parsed.caller = keys[0] ? String(keys[0]) : undefined;
            parsed.collection = keys[1] ? String(keys[1]) : undefined;
            parsed.document_id = keys[2] ? String(keys[2]) : undefined;
            parsed.old_data_hash = data[0] !== undefined ? String(data[0]) : undefined;
            parsed.new_data_hash = data[1] !== undefined ? String(data[1]) : undefined;
            parsed.timestamp = data[2] || undefined;
            break;
          case 'DocumentApproved':
            parsed.collection = keys[0] ? String(keys[0]) : undefined;
            parsed.document_id = keys[1] ? String(keys[1]) : undefined;
            parsed.creator = keys[2] ? String(keys[2]) : undefined;
            parsed.positive_votes = data[0] !== undefined ? Number(data[0]) : undefined;
            parsed.total_votes = data[1] !== undefined ? Number(data[1]) : undefined;
            parsed.timestamp = data[2] || undefined;
            break;
          case 'DocumentRejected':
            parsed.collection = keys[0] ? String(keys[0]) : undefined;
            parsed.document_id = keys[1] ? String(keys[1]) : undefined;
            parsed.creator = keys[2] ? String(keys[2]) : undefined;
            parsed.negative_votes = data[0] !== undefined ? Number(data[0]) : undefined;
            parsed.total_votes = data[1] !== undefined ? Number(data[1]) : undefined;
            parsed.timestamp = data[2] || undefined;
            break;
          case 'DocumentVoteSubmitted':
            parsed.voter = keys[0] ? String(keys[0]) : undefined;
            parsed.collection = keys[1] ? String(keys[1]) : undefined;
            parsed.document_id = keys[2] ? String(keys[2]) : undefined;
            parsed.creator = keys[3] ? String(keys[3]) : undefined;
            parsed.is_valid = data[0] !== undefined ? Boolean(data[0]) : undefined;
            parsed.positive_votes = data[1] !== undefined ? Number(data[1]) : undefined;
            parsed.negative_votes = data[2] !== undefined ? Number(data[2]) : undefined;
            parsed.timestamp = data[3] || undefined;
            break;
          default:
            // for unknown events, attempt to assign some common keys
            parsed.keys = keys;
            parsed.data = eventData.data;
        }
      } catch (err) {
        fastify.log.error('Error building parsed event: ' + err.message);
      }

      await storeEvent(transactionHash, eventName, eventData, indexed, receipt.block_number, parsed);
      storedEvents.push({
        eventName,
        eventData,
        indexed,
        parsed,
      });
    }

    return storedEvents;
  } catch (error) {
    fastify.log.error(`Error fetching transaction events: ${error.message}`);
    return [];
  }
};

const startEventListener = async () => {
  setInterval(async () => {
    try {
      const recentRequests = await Request.find({
        status: 'success',
        transactionHash: { $exists: true, $ne: null },
        createdAt: { $gte: new Date(Date.now() - 5 * 60 * 1000) },
      }).limit(10);

      for (const req of recentRequests) {
        const existingEvent = await ContractEvent.findOne({
          transactionHash: req.transactionHash,
        });

        if (!existingEvent) {
          const events = await fetchTransactionEvents(req.transactionHash);
          if (events.length > 0) {
            fastify.log.info(`Found ${events.length} events for transaction ${req.transactionHash}`);
          }
        }
      }
    } catch (error) {
      fastify.log.error(`Event listener error: ${error.message}`);
    }
  }, 5000);
};

// ==================== VALIDATION SCHEMAS ====================
const writeRequestSchema = {
  body: {
    type: 'object',
    required: ['methodName', 'arguments', 'walletAddress'],
    properties: {
      methodName: { type: 'string' },
      arguments: { type: 'object' },
      walletAddress: { type: 'string' },
    },
  },
};

// ==================== ERROR HANDLER ====================
fastify.setErrorHandler(async (error, request, reply) => {
  fastify.log.error(error);
  reply.status(500).send({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? error.message : 'An error occurred',
  });
});

// ==================== ROUTES ====================

// Health check
fastify.get('/health', async (request, reply) => {
  return { status: 'OK', message: 'Server is running', timestamp: new Date() };
});

// Write to smart contract
fastify.post('/write', { schema: writeRequestSchema }, async (request, reply) => {
  try {
    const { methodName, arguments: contractArguments, walletAddress } = request.body;

    fastify.log.info(`Write request received for method: ${methodName}`);
    fastify.log.info(`Arguments: ${JSON.stringify(contractArguments)}`);

    const request_record = new Request({
      walletAddress,
      methodName,
      arguments: contractArguments,
      status: 'pending',
    });

    await request_record.save();
    fastify.log.info(`Request saved to DB with ID: ${request_record._id}`);

    const contractAddress = process.env.CONTRACT_ADDRESS;
    
    fastify.log.info(`Fetching ABI from contract at: ${contractAddress}`);
    
    const classResponse = await provider.getClassAt(contractAddress);
    if (!classResponse?.abi) {
      throw new Error('Failed to fetch contract ABI from blockchain');
    }

    fastify.log.info('ABI fetched successfully');

    const contract = new Contract(classResponse.abi, contractAddress, provider);
    
    contract.connect(account);
    
    fastify.log.info(`Preparing call for method: ${methodName}`);
    
    const availableMethods = classResponse.abi
      .filter(item => item.type === 'function')
      .map(item => item.name);
    fastify.log.info(`Available contract methods: ${availableMethods.join(', ')}`);
    
    const methodExists = availableMethods.includes(methodName);
    if (!methodExists) {
      throw new Error(`Method "${methodName}" not found in contract. Available methods: ${availableMethods.join(', ')}`);
    }

    const callArgs = Object.keys(contractArguments).length > 0 ? [contractArguments] : [];
    const myCall = contract.populate(methodName, callArgs);
    
    fastify.log.info(`Executing contract method: ${methodName}`);

    const response = await contract[methodName](myCall.calldata);
    
    fastify.log.info(`Transaction submitted with hash: ${response.transaction_hash}`);
    
    fastify.log.info('Waiting for transaction confirmation...');
    const txReceipt = await provider.waitForTransaction(response.transaction_hash);
    
    fastify.log.info(`Transaction status: ${txReceipt.status}`);

    request_record.transactionHash = response.transaction_hash;
    request_record.status = txReceipt.isSuccess() ? 'success' : 'failed';
    request_record.updatedAt = new Date();
    
    if (!txReceipt.isSuccess()) {
      request_record.error = `Transaction failed with status: ${txReceipt.status}`;
    }
    
    await request_record.save();

    fastify.log.info(`Transaction ${txReceipt.isSuccess() ? 'successful' : 'failed'}: ${response.transaction_hash}`);

    return reply.status(200).send({
      success: txReceipt.isSuccess(),
      transactionHash: response.transaction_hash,
      requestId: request_record._id,
      status: txReceipt.status,
      message: txReceipt.isSuccess() ? 'Smart contract write completed successfully' : 'Transaction failed',
    });
  } catch (error) {
    fastify.log.error('Error writing to contract:', error.message);
    fastify.log.error('Full error:', error);

    if (request.body?.walletAddress) {
      await Request.findOneAndUpdate(
        { walletAddress: request.body.walletAddress, status: 'pending' },
        { 
          status: 'failed', 
          error: error.message,
          updatedAt: new Date(),
        },
        { sort: { createdAt: -1 } }
      );
    }

    return reply.status(500).send({
      success: false,
      error: 'Failed to write to smart contract',
      message: error.message,
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined,
    });
  }
});

// Get request status
fastify.get('/status/:requestId', async (request, reply) => {
  try {
    const { requestId } = request.params;

    const request_record = await Request.findById(requestId);

    if (!request_record) {
      return reply.status(404).send({ error: 'Request not found' });
    }

    return reply.status(200).send(request_record);
  } catch (error) {
    fastify.log.error('Error fetching request status:', error);
    return reply.status(500).send({
      error: 'Failed to fetch request status',
      message: error.message,
    });
  }
});

// Get all requests by wallet (paginated)
fastify.get('/requests/:walletAddress', async (request, reply) => {
  try {
    const { walletAddress } = request.params;
    const { page = 1, limit = 10 } = request.query;

    const skip = (page - 1) * limit;

    const requests = await Request.find({ walletAddress })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Request.countDocuments({ walletAddress });

    return reply.status(200).send({
      data: requests,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    fastify.log.error('Error fetching requests:', error);
    return reply.status(500).send({
      error: 'Failed to fetch requests',
      message: error.message,
    });
  }
});

// Get events by transaction hash
fastify.get('/events/tx/:transactionHash', async (request, reply) => {
  try {
    const { transactionHash } = request.params;

    const events = await ContractEvent.find({ transactionHash }).sort({ createdAt: -1 });

    return reply.status(200).send({
      transactionHash,
      eventCount: events.length,
      events,
    });
  } catch (error) {
    fastify.log.error('Error fetching events:', error);
    return reply.status(500).send({
      error: 'Failed to fetch events',
      message: error.message,
    });
  }
});

// Get events by event name
fastify.get('/events/name/:eventName', async (request, reply) => {
  try {
    const { eventName } = request.params;
    const { limit = 50, page = 1 } = request.query;

    const skip = (page - 1) * limit;

    const events = await ContractEvent.find({ eventName })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await ContractEvent.countDocuments({ eventName });

    return reply.status(200).send({
      eventName,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(total / limit),
      },
      events,
    });
  } catch (error) {
    fastify.log.error('Error fetching events by name:', error);
    return reply.status(500).send({
      error: 'Failed to fetch events',
      message: error.message,
    });
  }
});

// Get all events (filtered by type and date range)
fastify.get('/events', async (request, reply) => {
  try {
    const { eventName, startDate, endDate, limit = 100, page = 1 } = request.query;

    const filter = {};
    
    if (eventName) {
      filter.eventName = eventName;
    }

    if (startDate || endDate) {
      filter.createdAt = {};
      if (startDate) {
        filter.createdAt.$gte = new Date(startDate);
      }
      if (endDate) {
        filter.createdAt.$lte = new Date(endDate);
      }
    }

    const skip = (page - 1) * limit;

    const events = await ContractEvent.find(filter)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await ContractEvent.countDocuments(filter);

    return reply.status(200).send({
      filter,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(total / limit),
      },
      events,
    });
  } catch (error) {
    fastify.log.error('Error fetching all events:', error);
    return reply.status(500).send({
      error: 'Failed to fetch events',
      message: error.message,
    });
  }
});

// Get aggregated events / summary for a specific document (collection + docId)
fastify.get('/events/doc/:collection/:docId', async (request, reply) => {
  try {
    const { collection, docId } = request.params;

    // Find all events that mention this collection and docId in parsed fields or indexed keys
    const byParsed = await ContractEvent.find({
      $or: [
        { 'parsed.collection': collection, 'parsed.document_id': docId },
        { 'indexed.keys': { $in: [collection, docId] } }
      ]
    }).sort({ createdAt: -1 });

    if (!byParsed || byParsed.length === 0) {
      return reply.status(200).send({ collection, docId, events: [] });
    }

    // Build a summary: find latest DocumentInserted, count votes and approval status
    const summary = { collection, docId, inserted: null, approved: false, positive_votes: 0, negative_votes: 0, votes: [] };

    for (const ev of byParsed) {
      const p = ev.parsed || {};
      summary.events = summary.events || [];
      summary.events.push({ eventName: ev.eventName, parsed: p, tx: ev.transactionHash, createdAt: ev.createdAt });

      if (ev.eventName === 'DocumentInserted' && !summary.inserted) {
        summary.inserted = p;
      }

      if (ev.eventName === 'DocumentApproved') {
        summary.approved = true;
        if (typeof p.positive_votes === 'number') summary.positive_votes = p.positive_votes;
        if (typeof p.total_votes === 'number') summary.total_votes = p.total_votes;
      }

      if (ev.eventName === 'DocumentVoteSubmitted') {
        if (typeof p.positive_votes === 'number') summary.positive_votes = Math.max(summary.positive_votes, p.positive_votes);
        if (typeof p.negative_votes === 'number') summary.negative_votes = Math.max(summary.negative_votes, p.negative_votes);
        summary.votes.push(p);
      }
    }

    return reply.status(200).send({ success: true, summary });
  } catch (error) {
    fastify.log.error('Error fetching document summary:', error);
    return reply.status(500).send({ success: false, error: error.message });
  }
});

fastify.post('/events/fetch/:transactionHash', async (request, reply) => {
  try {
    const { transactionHash } = request.params;

    fastify.log.info(`Manually fetching events for: ${transactionHash}`);
    const events = await fetchTransactionEvents(transactionHash);

    return reply.status(200).send({
      success: true,
      transactionHash,
      eventCount: events.length,
      events,
    });
  } catch (error) {
    fastify.log.error('Error manually fetching events:', error);
    return reply.status(500).send({
      success: false,
      error: 'Failed to fetch events',
      message: error.message,
    });
  }
});

// ==================== SERVER START ====================
const start = async () => {
  try {
    const PORT = process.env.PORT || 3000;
    const HOST = process.env.HOST || '0.0.0.0';

    startEventListener();

    await fastify.listen({ port: PORT, host: HOST });
    fastify.log.info(`Server is running on ${HOST}:${PORT}`);
  } catch (error) {
    fastify.log.error('Failed to start server:', error);
    process.exit(1);
  }
};

start();