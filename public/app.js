const STORAGE_KEY = "safesub.mappingToken.v1";

const maskForm = document.querySelector("#mask-form");
const subscriptionForm = document.querySelector("#subscription-form");
const maskedResult = document.querySelector("#masked-result");
const subscriptionResult = document.querySelector("#subscription-result");
const maskedUri = document.querySelector("#masked-uri");
const mappingTokenField = document.querySelector("#mapping-token");
const subscriptionUrl = document.querySelector("#subscription-url");
const createSubscription = document.querySelector("#create-subscription");
const clearMapping = document.querySelector("#clear-mapping");
const mappingState = document.querySelector("#mapping-state");
const status = document.querySelector("#status");

let mappingToken = localStorage.getItem(STORAGE_KEY) ?? "";

function setStatus(message, kind = "") {
  status.textContent = message;
  if (kind === "") {
    delete status.dataset.kind;
  } else {
    status.dataset.kind = kind;
  }
}

function setMappingState(token) {
  mappingToken = token;
  createSubscription.disabled = token === "";
  clearMapping.hidden = token === "";
  mappingState.hidden = token === "";
  mappingTokenField.value = token;
}

function setBusy(form, busy) {
  for (const element of form.elements) {
    element.disabled = busy;
  }
  if (form === subscriptionForm && !busy) {
    createSubscription.disabled = mappingToken === "";
  }
  form.setAttribute("aria-busy", String(busy));
}

async function readApiResponse(response) {
  let body;
  try {
    body = await response.json();
  } catch {
    throw new Error("服务返回了无法识别的响应");
  }
  if (!response.ok) {
    const message = body?.error?.message;
    throw new Error(typeof message === "string" ? message : "请求失败");
  }
  return body;
}

async function postJson(path, body) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return readApiResponse(response);
}

async function copyValue(targetId, button) {
  const target = document.querySelector(`#${targetId}`);
  if (!(target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement)) {
    throw new Error("复制目标不存在");
  }

  try {
    await navigator.clipboard.writeText(target.value);
  } catch {
    target.focus();
    target.select();
    if (!document.execCommand("copy")) {
      throw new Error("自动复制失败，请手动复制");
    }
  }

  const original = button.textContent;
  button.textContent = "已复制";
  setTimeout(() => {
    button.textContent = original;
  }, 1400);
}

maskForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = new FormData(maskForm);
  setBusy(maskForm, true);
  setStatus("正在生成伪装节点");
  try {
    const result = await postJson("/api/mask", {
      vlessUri: data.get("vlessUri"),
      transport: data.get("transport") || "ws",
    });
    if (typeof result.maskedUri !== "string" || typeof result.mappingToken !== "string") {
      throw new Error("服务返回的数据不完整");
    }
    localStorage.setItem(STORAGE_KEY, result.mappingToken);
    setMappingState(result.mappingToken);
    maskedUri.value = result.maskedUri;
    maskedResult.hidden = false;
    subscriptionResult.hidden = true;
    setStatus("伪装节点已生成，映射已保存在此浏览器", "success");
  } catch (error) {
    setStatus(error instanceof Error ? error.message : "生成伪装节点失败", "error");
  } finally {
    setBusy(maskForm, false);
  }
});

subscriptionForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (mappingToken === "") {
    setStatus("请先生成伪装节点", "error");
    return;
  }

  const data = new FormData(subscriptionForm);
  setBusy(subscriptionForm, true);
  setStatus("正在生成最终订阅");
  try {
    const result = await postJson("/api/subscriptions", {
      mappingToken,
      upstreamUrl: data.get("upstreamUrl"),
    });
    if (typeof result.subscriptionUrl !== "string") {
      throw new Error("服务返回的数据不完整");
    }
    subscriptionUrl.value = result.subscriptionUrl;
    subscriptionResult.hidden = false;
    setStatus("最终订阅已生成", "success");
  } catch (error) {
    setStatus(error instanceof Error ? error.message : "生成最终订阅失败", "error");
  } finally {
    setBusy(subscriptionForm, false);
  }
});

clearMapping.addEventListener("click", () => {
  localStorage.removeItem(STORAGE_KEY);
  setMappingState("");
  maskedResult.hidden = true;
  subscriptionResult.hidden = true;
  setStatus("本地映射已清除");
});

document.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-copy-target]");
  if (!(button instanceof HTMLButtonElement)) {
    return;
  }
  try {
    await copyValue(button.dataset.copyTarget, button);
    setStatus("已复制到剪贴板", "success");
  } catch (error) {
    setStatus(error instanceof Error ? error.message : "复制失败", "error");
  }
});

setMappingState(mappingToken);
