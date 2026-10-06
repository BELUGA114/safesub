const STORAGE_KEY = "safesub.mappingToken.v1";

const directForm = document.querySelector("#direct-form");
const directResult = document.querySelector("#direct-result");
const directSubscriptionUrl = document.querySelector("#direct-subscription-url");
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
const directStatus = document.querySelector("#direct-status");
const maskStatus = document.querySelector("#mask-status");
const subscriptionStatus = document.querySelector("#subscription-status");

let mappingToken = localStorage.getItem(STORAGE_KEY) ?? "";

const statusAreas = [directStatus, maskStatus, subscriptionStatus];

// 提示落在触发操作的那个区块里：页面底部只有一个提示时，在顶部表单提交会看不到反馈。
// 一处更新就清掉其它区块的旧消息，避免同时留着互相矛盾的两条提示。
function setStatus(target, message, kind = "") {
  for (const area of statusAreas) {
    if (area === target) {
      continue;
    }
    area.textContent = "";
    delete area.dataset.kind;
  }

  target.textContent = message;
  if (kind === "") {
    delete target.dataset.kind;
  } else {
    target.dataset.kind = kind;
  }

  // 结果块展开后可能把提示挤出视口，就近滚回来，保证任何位置提交都能看到反馈。
  target.scrollIntoView({ block: "nearest" });
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

directForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = new FormData(directForm);
  const transport = data.get("transport");
  setBusy(directForm, true);
  setStatus(directStatus, "正在直接生成最终订阅");
  try {
    const result = await postJson("/api/direct", {
      vlessUri: data.get("vlessUri"),
      provider: data.get("provider"),
      // 空值表示跟随真实节点，不发送该字段
      ...(transport ? { transport } : {}),
    });
    if (typeof result.subscriptionUrl !== "string") {
      throw new Error("服务返回的数据不完整");
    }
    directSubscriptionUrl.value = result.subscriptionUrl;
    directResult.hidden = false;
    setStatus(directStatus, "最终订阅已生成", "success");
  } catch (error) {
    setStatus(directStatus, error instanceof Error ? error.message : "生成最终订阅失败", "error");
  } finally {
    setBusy(directForm, false);
  }
});

maskForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = new FormData(maskForm);
  setBusy(maskForm, true);
  setStatus(maskStatus, "正在生成伪装节点");
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
    setStatus(maskStatus, "伪装节点已生成，映射已保存在此浏览器", "success");
  } catch (error) {
    setStatus(maskStatus, error instanceof Error ? error.message : "生成伪装节点失败", "error");
  } finally {
    setBusy(maskForm, false);
  }
});

subscriptionForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (mappingToken === "") {
    setStatus(maskStatus, "请先生成伪装节点", "error");
    return;
  }

  const data = new FormData(subscriptionForm);
  const transport = data.get("transport");
  setBusy(subscriptionForm, true);
  setStatus(subscriptionStatus, "正在生成最终订阅");
  try {
    const result = await postJson("/api/subscriptions", {
      mappingToken,
      upstreamUrl: data.get("upstreamUrl"),
      // 空值表示跟随真实节点，不发送该字段
      ...(transport ? { transport } : {}),
    });
    if (typeof result.subscriptionUrl !== "string") {
      throw new Error("服务返回的数据不完整");
    }
    subscriptionUrl.value = result.subscriptionUrl;
    subscriptionResult.hidden = false;
    setStatus(subscriptionStatus, "最终订阅已生成", "success");
  } catch (error) {
    setStatus(subscriptionStatus, error instanceof Error ? error.message : "生成最终订阅失败", "error");
  } finally {
    setBusy(subscriptionForm, false);
  }
});

clearMapping.addEventListener("click", () => {
  localStorage.removeItem(STORAGE_KEY);
  setMappingState("");
  maskedResult.hidden = true;
  subscriptionResult.hidden = true;
  setStatus(maskStatus, "本地映射已清除");
});

document.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-copy-target]");
  if (!(button instanceof HTMLButtonElement)) {
    return;
  }
  // 复制反馈落在按钮所在区块的提示元素里。
  const target = button.closest("section")?.querySelector(".status");
  if (!(target instanceof HTMLElement)) {
    return;
  }
  try {
    await copyValue(button.dataset.copyTarget, button);
    setStatus(target, "已复制到剪贴板", "success");
  } catch (error) {
    setStatus(target, error instanceof Error ? error.message : "复制失败", "error");
  }
});

setMappingState(mappingToken);
