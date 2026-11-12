'use strict';

// guard -> chat (memory writer) -> classify -> embed, using only fetch + require.
// Run the loader first (cargo run --release), then: node examples/full-flow.js "your text"
const loader = require('../gateway/loader-client');

async function main() {
  const text = process.argv[2] || 'We tried Postgres, too slow, switched to SQLite';

  const verdict = await loader.guard('guard', text);
  if (verdict.blocked) {
    console.log(`Blocked by guard (${verdict.label}, ${verdict.score.toFixed(2)}). Nothing stored.`);
    return;
  }

  const chat = await loader.chat(
    'qwen3-0-6b',
    [
      { role: 'system', content: 'You are a memory writer. Return only JSON.' },
      { role: 'user', content: text },
    ],
    { temperature: 0, max_tokens: 200, format: 'json' },
  );
  const memory = JSON.parse(chat.choices[0].message.content);

  const kind = await loader.classify('memory-classifier', memory.text || text);
  const { embedding, dim } = await loader.embed('bge-small', memory.text || text);

  console.log({ memory, type: kind.label, score: kind.score, dim, first: embedding.slice(0, 4) });
}

main().catch((err) => {
  console.error(`${err.code || 'ERROR'}: ${err.message}`);
  process.exit(1);
});
