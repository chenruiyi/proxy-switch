export function Toggle(): Promise<void>;

export function GetState(): Promise<boolean>;

export function GetProxyIP(): Promise<string>;

export function UpdateProxyIP(ip: string): Promise<void>;

export function IsMacOS(): Promise<boolean>;

export function Quit(): Promise<void>;

export function SubmitSudoPassword(pw: string): Promise<void>;

export function HasSudoPassword(): Promise<boolean>;
