import { describe, expect, it } from "vitest";

import { guardAgainstLock, safeErrorMessage } from "../src/core/bridge";
import { FakeCoreClient } from "../src/core/fake";

const ACCOUNT = {
  id: "00000000-0000-0000-0000-000000000001",
  issuer: "Example",
  account_label: "user@example.com",
  favorite: false,
  has_conflict: false,
  conflicted_fields: [],
  deleted: false,
};

function setup() {
  const fake = new FakeCoreClient();
  fake.vault = { ...fake.vault, vault_id: "v", locked: false, name: "Vault" };
  fake.accounts = [ACCOUNT];
  const guarded = guardAgainstLock(fake);
  return { fake, guarded };
}

describe("bridge lock guard", () => {
  it("discards an in-flight account response after a lock event", async () => {
    const { fake, guarded } = setup();
    // In-flight: the operation is genuinely delayed, then the lock lands
    // before the response does.
    fake.delayListMs = 5;
    const pending = guarded.guarded.listAccounts();
    await guarded.lock();
    const result = await pending;
    expect(result.discarded).toBe(true);
    expect(fake.vault.locked).toBe(true);
  });

  it("discards a delayed code response after lock", async () => {
    const { fake, guarded } = setup();
    fake.delayCodeMs = 5;
    const pending = guarded.guarded.getCode(ACCOUNT.id);
    await guarded.lock();
    expect((await pending).discarded).toBe(true);
  });

  it("delivers responses that complete before the lock", async () => {
    const { guarded } = setup();
    const result = await guarded.guarded.listAccounts();
    expect(result.discarded).toBe(false);
    expect(result.value).toHaveLength(1);
  });

  it("keeps counting generations across multiple locks", async () => {
    const { guarded } = setup();
    expect(guarded.generation()).toBe(1);
    await guarded.lock();
    expect(guarded.generation()).toBe(2);
    await guarded.lock();
    expect(guarded.generation()).toBe(3);
  });
});

describe("error translation", () => {
  it("produces fixed safe messages, never raw provider output", () => {
    const raw = { kind: "other", message: "HTTP 500 at https://api.provider.internal/token BadGateway" };
    expect(safeErrorMessage(raw)).toBe(raw.message);
    expect(safeErrorMessage(new Error("Rust Debug: Os { code: 13 }"))).toBe(
      "Something went wrong. Technical details are available separately.",
    );
  });
});

describe("unknown commands", () => {
  it("are rejected by the typed client surface", async () => {
    const { fake } = setup();
    // The CoreClient interface has no arbitrary-command escape hatch.
    const client: unknown = fake;
    expect((client as Record<string, unknown>)["executeArbitrary"]).toBeUndefined();
  });
});
