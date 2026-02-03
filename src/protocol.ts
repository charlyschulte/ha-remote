export type ServerToClient =
  | { type: "authed"; subdomain: string }
  | { type: "http_req"; id: string; method: string; path: string; headers: Record<string, string>; bodyBase64?: string }
  | { type: "ws_open"; id: string; path: string; headers: Record<string, string>; protocols?: string[] }
  | { type: "ws_data"; id: string; dataBase64: string }
  | { type: "ws_close"; id: string }
  | { type: "err"; message: string };

export type ClientToServer =
  | { type: "auth"; token: string; haVersion?: string; addonVersion?: string }
  | { type: "http_res"; id: string; status: number; headers?: Record<string, string>; bodyBase64?: string }
  | { type: "http_res_start"; id: string; status: number; headers?: Record<string, string> }
  | { type: "http_res_chunk"; id: string; dataBase64: string }
  | { type: "http_res_end"; id: string }
  | { type: "ws_data"; id: string; dataBase64: string }
  | { type: "ws_close"; id: string }
  | { type: "ping" };
