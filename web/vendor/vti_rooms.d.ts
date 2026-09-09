/* tslint:disable */
/* eslint-disable */

/**
 * One room this browser can open.
 *
 * Holds the MLS group and the epoch key chain. Every method that resolves a key takes
 * `&mut self`, because walking the chain memoises what it derives — opening a room's
 * history is one walk, not one per record.
 */
export class RoomMember {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * See [`RoomMember::add_links`].
     */
    addLinks(links: string): void;
    /**
     * See [`RoomMember::apply_commit`].
     */
    applyCommit(commit: Uint8Array): string;
    /**
     * See [`RoomMember::earliest_readable_epoch`].
     */
    earliestReadableEpoch(): number;
    /**
     * See [`RoomMember::join`].
     */
    static join(room_id: string, minted: string, welcome: Uint8Array, invitation: string, spent: string): RoomMember;
    /**
     * See [`RoomMember::open_record`].
     */
    openRecord(key: string, version: bigint, sealed: string): Uint8Array;
    /**
     * See [`RoomMember::restore`].
     */
    static restore(snapshot: string): RoomMember;
    /**
     * See [`RoomMember::seal_record`].
     */
    sealRecord(key: string, version: bigint, plaintext: Uint8Array): string;
    /**
     * See [`RoomMember::snapshot`].
     */
    snapshot(): string;
    /**
     * See [`RoomMember::epoch`].
     */
    readonly epoch: number;
    /**
     * See [`RoomMember::room_id`].
     */
    readonly roomId: string;
}

/**
 * See [`mint_key_package`].
 */
export function mintKeyPackage(member_did: string, room_id: string, invitation: string, spent: string): string;

/**
 * Run the five invitation checks and return the credential id to record as spent.
 *
 * Exposed separately from [`mint_key_package`] so a surface can *show* the checks — which
 * is most of what a person needs to understand about a room they are being let into.
 */
export function verifyInvitation(invitation: string, room_id: string, member_did: string, spent: string): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_roommember_free: (a: number, b: number) => void;
    readonly mintKeyPackage: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => void;
    readonly roommember_addLinks: (a: number, b: number, c: number, d: number) => void;
    readonly roommember_applyCommit: (a: number, b: number, c: number, d: number) => void;
    readonly roommember_earliestReadableEpoch: (a: number, b: number) => void;
    readonly roommember_epoch: (a: number) => number;
    readonly roommember_join: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number) => void;
    readonly roommember_openRecord: (a: number, b: number, c: number, d: number, e: bigint, f: number, g: number) => void;
    readonly roommember_restore: (a: number, b: number, c: number) => void;
    readonly roommember_roomId: (a: number, b: number) => void;
    readonly roommember_sealRecord: (a: number, b: number, c: number, d: number, e: bigint, f: number, g: number) => void;
    readonly roommember_snapshot: (a: number, b: number) => void;
    readonly verifyInvitation: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => void;
    readonly __wbindgen_export: (a: number) => void;
    readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
    readonly __wbindgen_export2: (a: number, b: number) => number;
    readonly __wbindgen_export3: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_export4: (a: number, b: number, c: number) => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
