declare module "node:fs";
declare module "node:path";
declare module "node:child_process";

declare const console: {
  log: (...args: any[]) => void;
  warn: (...args: any[]) => void;
  error: (...args: any[]) => void;
};

declare const process: {
  env: Record<string, string | undefined>;
  exit: (code?: number) => never;
};

declare function setTimeout(
  handler: (...args: any[]) => void,
  timeout?: number,
  ...args: any[]
): any;

declare function fetch(input: any, init?: any): Promise<any>;

declare const Buffer: {
  from: (input: any) => { toString: (encoding?: string) => string };
};
