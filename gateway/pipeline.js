'use strict';

/**
 * The memory flow from the spec, in one call:
 *   1. guard the input      (blocked -> stop, nothing else runs)
 *   2. chat: memory writer  (JSON out)
 *   3. classify the memory
 *   4. embed the memory text
 * Each step reports its own status and timing so a UI can show where it stopped.
 */

const DEFAULT_SYSTEM =
  'You are a memory writer. Return only JSON like {"type":"episodic|semantic|procedural","text":"<one short sentence>"}.';

async function timed(fn) {
  const t0 = Date.now();
  try {
    const result = await fn();
    return { status: 'ok', ms: Date.now() - t0, result };
  } catch (err) {
    return {
      status: 'error',
      ms: Date.now() - t0,
      error: { code: err.code || 'INTERNAL_ERROR', message: err.message, model: err.model || null },
    };
  }
}

function parseMemory(content) {
  try {
    const obj = JSON.parse(content);
    if (obj && typeof obj.text === 'string') return obj;
  } catch {
    /* fall through */
  }
  return null;
}

/**
 * @param {ReturnType<import('./loader-client').createClient>} loader
 * @param {{text:string, guard?:string, writer?:string, classifier?:string, embedder?:string, system?:string}} input
 */
async function runPipeline(loader, input) {
  const steps = [];
  const skip = (name) => steps.push({ name, status: 'skipped' });
  const run = async (name, fn) => {
    const step = { name, ...(await timed(fn)) };
    steps.push(step);
    return step;
  };

  // 1. Guard. Fail safe: an error here stops the flow just like a block.
  if (input.guard) {
    const guard = await run('guard', () => loader.guard(input.guard, input.text));
    if (guard.status === 'ok' && guard.result.blocked) {
      guard.status = 'blocked';
    }
    if (guard.status !== 'ok') {
      for (const name of ['chat', 'classify', 'embed']) skip(name);
      return { steps, blocked: guard.status === 'blocked', memory: null };
    }
  } else {
    skip('guard');
  }

  // 2. Memory writer.
  let memoryText = input.text;
  let memory = null;
  if (input.writer) {
    const chat = await run('chat', () =>
      loader.chat(
        input.writer,
        [
          { role: 'system', content: input.system || DEFAULT_SYSTEM },
          { role: 'user', content: input.text },
        ],
        { temperature: 0, max_tokens: 200, format: 'json' },
      ),
    );
    if (chat.status === 'ok') {
      const content = chat.result.choices?.[0]?.message?.content ?? '';
      memory = parseMemory(content);
      chat.result = { content, parsed: memory };
      if (memory) memoryText = memory.text;
    }
  } else {
    skip('chat');
  }

  // 3. Classify the memory type.
  if (input.classifier) {
    await run('classify', () => loader.classify(input.classifier, memoryText));
  } else {
    skip('classify');
  }

  // 4. Embed the memory text.
  if (input.embedder) {
    await run('embed', async () => {
      const r = await loader.embed(input.embedder, memoryText);
      // Only a preview comes back: the full vector belongs in your own store.
      return { dim: r.dim, preview: r.embedding.slice(0, 8) };
    });
  } else {
    skip('embed');
  }

  return { steps, blocked: false, memory: { text: memoryText, writer: memory } };
}

module.exports = { runPipeline, DEFAULT_SYSTEM };
