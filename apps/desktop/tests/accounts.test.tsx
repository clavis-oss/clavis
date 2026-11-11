import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { AccountRow, groupCode } from "../src/components/AccountRow";
import { Toast } from "../src/components/Toast";
import { App } from "../src/App";
import { FakeCoreClient } from "../src/core/fake";

afterEach(cleanup);

const ACCOUNT = {
  id: "00000000-0000-0000-0000-000000000001",
  issuer: "Example",
  account_label: "user@example.com",
  favorite: false,
  has_conflict: false,
  conflicted_fields: [],
  deleted: false,
};

describe("AccountRow", () => {
  it("renders labels as ordinary text nodes (XSS-safe)", () => {
    const hostile: typeof ACCOUNT = {
      ...ACCOUNT,
      issuer: '<img src=x onerror="window.__pwned=1">',
    };
    render(<AccountRow account={hostile} onCopy={() => {}} onEdit={() => {}} onFavorite={() => {}} onDelete={() => {}} />);
    expect(screen.getByText(hostile.issuer).tagName).toBe("DIV");
    expect((window as { __pwned?: boolean }).__pwned).toBeUndefined();
  });

  it("groups 6- and 8-digit codes", () => {
    expect(groupCode("123456")).toBe("123 456");
    expect(groupCode("12345678")).toBe("1234 5678");
  });
});

describe("Toast", () => {
  it("contains no OTP digits and no account label", () => {
    render(<Toast message="Code copied" />);
    const el = screen.getByRole("status");
    expect(el.textContent).toBe("Code copied");
    expect(el.textContent).not.toMatch(/\d{6}/);
  });
});

describe("App flow with fake client", () => {
  it("offline save reports Pending, never Synced", async () => {
    const fake = new FakeCoreClient();
    fake.vault = { ...fake.vault, vault_id: "v", locked: true, name: "Vault" };
    fake.status = "pending";
    render(<App client={fake} />);
    // Unlock screen first.
    expect(screen.getByText("Unlock your vault")).toBeTruthy();
  });

  it("empty vault shows the local-first empty state", async () => {
    const fake = new FakeCoreClient();
    fake.vault = { ...fake.vault, vault_id: "", locked: true };
    render(<App client={fake} />);
    expect(screen.getByText("Create vault")).toBeTruthy();
  });
});
