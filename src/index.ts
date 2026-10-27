import * as core from '@actions/core';
import { main } from './main.ts';

main().catch((err: unknown) => {
  core.setFailed(err instanceof Error ? err.message : String(err));
});
