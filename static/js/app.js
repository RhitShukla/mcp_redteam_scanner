// NEXUS — Tech/Gadgets storefront logic

const products = [
  {
    id: 1, name: "Quantum Laptop Pro", price: 1299,
    desc: "14-inch 3K OLED, M4 Max, 32GB RAM, 1TB SSD. For developers who refuse to compromise.",
    image: "/static/images/laptop.jpg",
    tag: "Laptop"
  },
  {
    id: 2, name: "Nova Phone X", price: 899,
    desc: "Titanium frame, 6.8-inch LTPO display, 200MP camera, satellite messaging.",
    image: "/static/images/phone.jpg",
    tag: "Phone"
  },
  {
    id: 3, name: "Aura Buds Pro", price: 199,
    desc: "Active noise cancellation, spatial audio, 30-hour battery, IPX4 water resistant.",
    image: "/static/images/buds.jpg",
    tag: "Audio"
  },
  {
    id: 4, name: "Titan Watch Ultra", price: 349,
    desc: "Titanium case, always-on Retina, ECG, blood oxygen, 36-hour battery.",
    image: "/static/images/watch.jpg",
    tag: "Wearable"
  },
  {
    id: 5, name: "Pixel Cam 4K", price: 549,
    desc: "4K 60fps, 1-inch sensor, 3-axis gimbal, 100m waterproof housing.",
    image: "/static/images/camera.jpg",
    tag: "Camera"
  },
  {
    id: 6, name: "Neon Mechanical Keyboard", price: 169,
    desc: "Hot-swappable switches, per-key RGB, aluminum chassis, PBT keycaps.",
    image: "/static/images/keyboard.jpg",
    tag: "Accessory"
  },
  {
    id: 7, name: "Curve Monitor 34\"", price: 649,
    desc: "UltraWide WQHD, 144Hz, 1ms response, USB-C with 90W power delivery.",
    image: "/static/images/monitor.jpg",
    tag: "Monitor"
  },
  {
    id: 8, name: "Pulse Smart Speaker", price: 129,
    desc: "360-degree audio, adaptive EQ, voice assistant, IP67 rugged design.",
    image: "/static/images/speaker.jpg",
    tag: "Audio"
  },
];

let cart = JSON.parse(localStorage.getItem("nexus_cart")) || [];

const productGrid = document.getElementById("productGrid");
const cartItemsEl = document.getElementById("cartItems");
const cartTotalEl = document.getElementById("cartTotal");
const cartBadge = document.getElementById("cart-count");
const cartDrawer = document.getElementById("cartDrawer");
const cartOverlay = document.getElementById("cartOverlay");
const modalOverlay = document.getElementById("modalOverlay");
const productModal = document.getElementById("productModal");
const detailImage = document.getElementById("detailImage");
const detailName = document.getElementById("detailName");
const detailPrice = document.getElementById("detailPrice");
const detailDesc = document.getElementById("detailDesc");
const checkoutTotalEl = document.getElementById("checkoutTotal");
const checkoutMsg = document.getElementById("checkoutMsg");
const checkoutForm = document.getElementById("checkoutForm");
let detailProductId = null;

function placeholderImg() {
  // Use a reliable placeholder service instead of raw SVG string to avoid encoding issues in attributes
  return "https://via.placeholder.com/600x400/1e293b/64748b?text=NEXUS+Tech";
}

function renderProducts() {
  if (!productGrid) return;
  productGrid.innerHTML = products.map(p => `
    <article class="product-card" data-id="${p.id}">
      <div class="card-image">
        <img src="${p.image}" alt="${p.name}" 
          onerror="this.onerror=null;this.src='${placeholderImg()}'"/>
        <span class="card-tag">${p.tag}</span>
      </div>
      <div class="card-body">
        <div class="card-name">${p.name}</div>
        <div class="card-desc">${p.desc}</div>
      </div>
      <div class="card-footer">
        <div class="card-price">$${p.price.toLocaleString()}</div>
        <button class="card-btn" aria-label="Add ${p.name}" onclick="event.stopPropagation(); addToCart(${p.id})">+</button>
      </div>
    </article>
  `).join("");
}

function renderCart() {
  if (!cartItemsEl) return;
  cartItemsEl.innerHTML = "";
  let total = 0;
  if (cart.length === 0) {
    cartItemsEl.innerHTML = '<div style="padding:2rem;color:var(--text-muted);text-align:center;">Your cart is empty.</div>';
  } else {
    cart.forEach((item, idx) => {
      total += item.price * item.qty;
      cartItemsEl.innerHTML += `
        <div class="cart-item">
          <img src="${item.image}" alt="${item.name}" class="cart-item-thumb"
            onerror="this.onerror=null;this.src='${placeholderImg()}'"/>
          <div class="cart-item-info">
            <div class="cart-item-name">${item.name}</div>
            <div class="cart-item-price">$${item.price.toLocaleString()}</div>
            <div class="cart-item-qty">Qty: ${item.qty}</div>
          </div>
          <div class="cart-item-remove" onclick="removeFromCart(${idx})" aria-label="Remove">×</div>
        </div>
      `;
    });
  }
  if (cartTotalEl) cartTotalEl.textContent = "$" + total.toLocaleString(undefined, {minimumFractionDigits:2, maximumFractionDigits:2});
  if (cartBadge) cartBadge.textContent = cart.reduce((s, i) => s + i.qty, 0);
  if (checkoutTotalEl) checkoutTotalEl.textContent = total.toLocaleString(undefined, {minimumFractionDigits:2, maximumFractionDigits:2});
}

function addToCart(id) {
  const p = products.find(x => x.id === id);
  const existing = cart.find(i => i.id === id);
  if (existing) existing.qty += 1;
  else cart.push({...p, qty: 1});
  saveCart();
  renderCart();
  if (cartDrawer) cartDrawer.classList.add("open");
  if (cartOverlay) cartOverlay.classList.add("open");
}

function addToCartFromDetail() {
  if (!detailProductId) return;
  addToCart(detailProductId);
  closeProduct();
}

function removeFromCart(idx) {
  cart.splice(idx, 1);
  saveCart();
  renderCart();
}

function saveCart() {
  localStorage.setItem("nexus_cart", JSON.stringify(cart));
}

function toggleCart() {
  if (!cartDrawer || !cartOverlay) return;
  const open = cartDrawer.classList.toggle("open");
  cartOverlay.classList.toggle("open", open);
}

function openProduct(id) {
  const p = products.find(x => x.id === id);
  if (!p || !productModal || !modalOverlay) return;
  detailProductId = id;
  detailImage.innerHTML = `<img src="${p.image}"
    onerror="this.onerror=null;this.src='${placeholderImg()}'"
    alt="${p.name}"/>`;
  detailName.textContent = p.name;
  detailPrice.textContent = "$" + p.price.toLocaleString();
  detailDesc.textContent = p.desc;
  modalOverlay.classList.add("open");
  productModal.classList.add("open");
  document.body.style.overflow = "hidden"; // Prevent background scroll
}

function closeProduct() {
  if (!productModal || !modalOverlay) return;
  modalOverlay.classList.remove("open");
  productModal.classList.remove("open");
  detailProductId = null;
  document.body.style.overflow = "";
}

// Attach product click handlers
document.addEventListener("click", (e) => {
  const card = e.target.closest(".product-card");
  if (card && !e.target.closest(".card-btn, .cart-item-remove, .btn-close")) {
    const id = parseInt(card.dataset.id);
    openProduct(id);
  }
});

// Close modal/cart on Escape key
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    closeProduct();
    if (cartDrawer) cartDrawer.classList.remove("open");
    if (cartOverlay) cartOverlay.classList.remove("open");
    const chatWidget = document.getElementById("chatWidget");
    if (chatWidget) chatWidget.classList.remove("open");
  }
});

function checkout() {
  if (cart.length === 0) {
    alert("Your cart is empty.");
    return;
  }
  const section = document.getElementById("checkout");
  if (section) {
    section.style.display = "block";
    section.scrollIntoView({ behavior: "smooth" });
  }
}

if (checkoutForm) {
  checkoutForm.addEventListener("submit", (e) => {
    e.preventDefault();
    checkoutMsg.textContent = "";
    checkoutMsg.className = "msg";
    setTimeout(() => {
      checkoutMsg.textContent = "Order placed successfully (demo). Thank you!";
      checkoutMsg.className = "msg success";
      cart = [];
      saveCart();
      renderCart();
      if (cartDrawer) cartDrawer.classList.remove("open");
      if (cartOverlay) cartOverlay.classList.remove("open");
      checkoutForm.reset();
    }, 600);
  });
}


// ── AI Agent Chat Sandbox Logic ──

const chatWidget = document.getElementById("chatWidget");
const chatMessages = document.getElementById("chatMessages");
const chatForm = document.getElementById("chatForm");
const chatInput = document.getElementById("chatInput");

function toggleChat() {
  if (!chatWidget) return;
  chatWidget.classList.toggle("open");
  if (chatWidget.classList.contains("open") && chatInput) {
    chatInput.focus();
  }
}

async function sendSuggestion(text) {
  if (!chatInput) return;
  chatInput.value = text;
  submitChatMessage();
}

async function submitChatMessage() {
  const text = chatInput.value.trim();
  if (!text) return;

  // Append user message
  appendMessage("user", text);
  chatInput.value = "";

  // Append thinking bot message
  const thinkingId = appendMessage("bot", '<span class="pulse">...thinking...</span>');

  try {
    const res = await fetch("/api/agent/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: text })
    });

    const data = await res.json();
    const thinkingEl = document.getElementById(thinkingId);
    if (thinkingEl) thinkingEl.remove();

    if (data.response) {
      appendMessage("bot", data.response);
    }

    if (data.traces && data.traces.length > 0) {
      data.traces.forEach(trace => {
        if (trace.request && trace.response) {
          appendTraceMessage(trace.tool, trace.request, trace.response);
        }
      });
    }
  } catch (e) {
    const thinkingEl = document.getElementById(thinkingId);
    if (thinkingEl) thinkingEl.remove();
    appendMessage("bot", "Error connecting to AI Agent host. Is the FastAPI server running?");
  }
}

function appendMessage(sender, html) {
  const id = "msg-" + Date.now() + Math.random().toString(36).substr(2, 5);
  const div = document.createElement("div");
  div.id = id;
  div.className = `chat-msg ${sender}`;
  div.innerHTML = html;
  if (chatMessages) {
    chatMessages.appendChild(div);
    chatMessages.scrollTop = chatMessages.scrollHeight;
  }
  return id;
}

function appendTraceMessage(tool, request, response) {
  const div = document.createElement("details");
  div.className = "chat-msg trace";
  div.innerHTML = `
    <summary>⚙️ MCP Tool Call: ${tool}</summary>
    <pre><strong>JSON-RPC Request:</strong>\n${JSON.stringify(request, null, 2)}\n\n<strong>JSON-RPC Response:</strong>\n${JSON.stringify(response, null, 2)}</pre>
  `;
  if (chatMessages) {
    chatMessages.appendChild(div);
    chatMessages.scrollTop = chatMessages.scrollHeight;
  }
}

if (chatForm) {
  chatForm.addEventListener("submit", (e) => {
    e.preventDefault();
    submitChatMessage();
  });
}

// Global Suggestion router helper
window.sendSuggestion = sendSuggestion;
window.toggleChat = toggleChat;

// Init
renderProducts();
renderCart();
