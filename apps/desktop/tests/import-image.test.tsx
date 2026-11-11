import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { App } from "../src/App";
import { FakeCoreClient } from "../src/core/fake";

afterEach(cleanup);

function unlockedApp() {
  const fake = new FakeCoreClient();
  fake.vault = { vault_id: "v", name: "Vault", provider_kind: null, locked: false, has_conflicts: false };
  return fake;
}

describe("QR image import", () => {
  it("shows a chooser when the image contains multiple QR codes", async () => {
    const fake = unlockedApp();
    fake.multiQrCandidates = 3;
    fake.accounts = [];
    const { container } = render(<App client={fake} />);
        await waitFor(() => screen.getAllByRole("button", { name: "Add account" }).length > 0);
    fireEvent.click(screen.getAllByRole("button", { name: "Add account" })[0]);
    fireEvent.click(screen.getByRole("tab", { name: "QR image" }));
    // Simulate a picked file by driving the fake directly through the UI:
    // the file input itself needs a real File; use the manual path guard.
    const input = container.querySelector('input[type="file"]') as HTMLInputElement;
    const file = new File([new Uint8Array([1, 2, 3])], "qr.png", { type: "image/png" });
    fireEvent.change(input, { target: { files: [file] } });
    // Wait until the picked file name is reflected (onChange ran).
    await waitFor(() => screen.getByText(/Selected: qr\.png/));
    // Selecting a file enables Preview; clicking it runs the (fake) decode
    // which reports multiple candidates.
    const previewBtn = await waitFor(() => {
      const b = screen.getByRole("button", { name: "Preview" }) as HTMLButtonElement;
      if (b.disabled) throw new Error("preview not enabled yet");
      return b;
    });
    fireEvent.click(previewBtn);
    await waitFor(() => screen.getByText(/contains 3 QR codes/));
    fireEvent.click(screen.getByText("Use QR code 2"));
    // The preview panel appeared with the fictional fixture account.
    await waitFor(() => expect(screen.getByText("Example")).toBeTruthy());
  });

  it("empty image bytes are rejected with a safe message", async () => {
    const fake = unlockedApp();
    const err = await fake.previewImportImage([]).catch((e) => e);
    expect(err.kind).toBe("invalid_input");
  });
});

describe("live codes", () => {
  it("listCodes returns a code per non-conflicted account and none for conflicted", async () => {
    const fake = unlockedApp();
    fake.accounts = [
      { id: "00000000-0000-0000-0000-000000000001", issuer: "A", account_label: "a@x", favorite: false, has_conflict: false, conflicted_fields: [], deleted: false },
      { id: "00000000-0000-0000-0000-000000000002", issuer: "B", account_label: "b@x", favorite: false, has_conflict: true, conflicted_fields: ["otp_config"], deleted: false },
    ];
    const codes = await fake.listCodes();
    expect(codes).toHaveLength(1);
    expect(codes[0].account_id).toBe("00000000-0000-0000-0000-000000000001");
    expect(codes[0].value).toMatch(/^\d{6}$/);
    // getCode on the conflicted account is refused.
    await expect(fake.getCode("00000000-0000-0000-0000-000000000002")).rejects.toMatchObject({
      kind: "invalid_input",
    });
  });
});
