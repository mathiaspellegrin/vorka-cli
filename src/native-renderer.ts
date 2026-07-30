interface Drive {
  path: string;
  label: string;
  configured: boolean;
  damaged: boolean;
  problem?: string;
}

interface VorkaApi {
  listDrives(): Promise<Drive[]>;
  generate(request: { drivePath: string; authPassword: string; fallbackPassword: string }): Promise<{
    authAddress: string;
    fallbackAddress: string;
  }>;
}

declare global { interface Window { vorka: VorkaApi } }

const element = <T extends HTMLElement>(id: string): T => {
  const value = document.getElementById(id);
  if (!value) throw new Error(`Missing UI element: ${id}`);
  return value as T;
};

const setup = element("setup");
const errorBox = element("error");
const success = element("success");
const statusTitle = element("statusTitle");
const statusPath = element("statusPath");
const dot = element("dot");
const driveSelect = element<HTMLSelectElement>("drive");
const createButton = element<HTMLButtonElement>("create");

function showError(error: unknown): void {
  errorBox.textContent = error instanceof Error ? error.message : String(error);
  errorBox.classList.remove("hidden");
}

async function refresh(): Promise<void> {
  errorBox.classList.add("hidden");
  try {
    const drives = await window.vorka.listDrives();
    const available = drives.filter((drive) => !drive.configured && !drive.damaged);
    driveSelect.replaceChildren(...available.map((drive) => {
      const option = document.createElement("option");
      option.value = drive.path;
      option.textContent = `${drive.label} — ${drive.path}`;
      return option;
    }));
    if (available.length > 0) {
      dot.classList.add("ok");
      statusTitle.textContent = "Vorka Key detected";
      statusPath.textContent = available[0].path;
      setup.classList.remove("hidden");
      return;
    }
    const damaged = drives.find((drive) => drive.damaged);
    const configured = drives.find((drive) => drive.configured);
    dot.classList.toggle("ok", Boolean(configured) && !damaged);
    statusTitle.textContent = damaged
      ? "This Vorka Key needs attention"
      : configured ? "This Vorka Key is already configured" : "No unconfigured Vorka Key detected";
    statusPath.textContent = damaged
      ? `${damaged.problem ?? "The key bundle is damaged"} — ${damaged.path}`
      : configured ? configured.path : "Plug in a valid provisioned Vorka USB, then refresh.";
    setup.classList.add("hidden");
  } catch (error) {
    showError(error);
  }
}

element("refresh").addEventListener("click", () => void refresh());
driveSelect.addEventListener("change", () => { statusPath.textContent = driveSelect.value; });
createButton.addEventListener("click", async () => {
  errorBox.classList.add("hidden");
  const auth = element<HTMLInputElement>("auth");
  const auth2 = element<HTMLInputElement>("auth2");
  const fallback = element<HTMLInputElement>("fallback");
  const fallback2 = element<HTMLInputElement>("fallback2");
  if (auth.value !== auth2.value) return showError("Daily-use passwords do not match.");
  if (fallback.value !== fallback2.value) return showError("Recovery passwords do not match.");
  if (auth.value === fallback.value) return showError("The two passwords must be different.");
  createButton.disabled = true;
  createButton.textContent = "Creating keys…";
  try {
    const result = await window.vorka.generate({
      drivePath: driveSelect.value,
      authPassword: auth.value,
      fallbackPassword: fallback.value,
    });
    auth.value = auth2.value = fallback.value = fallback2.value = "";
    setup.classList.add("hidden");
    success.classList.remove("hidden");
    element("authAddress").textContent = result.authAddress;
    element("fallbackAddress").textContent = result.fallbackAddress;
    statusTitle.textContent = "Configuration complete";
  } catch (error) {
    showError(error);
    createButton.disabled = false;
    createButton.textContent = "Create encrypted keys";
  }
});

void refresh();
window.setInterval(() => { if (success.classList.contains("hidden")) void refresh(); }, 4000);

export {};
