function activeSection() {
  const links = [...document.querySelectorAll(".site-menu a[href*='#']")].filter(
    (link) => new URL(link.href).pathname === location.pathname,
  );
  const targets = links
    .map((link) => document.getElementById(new URL(link.href).hash.slice(1)))
    .filter(Boolean);
  if (!targets.length) return;

  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        for (const link of links) {
          if (new URL(link.href).hash === `#${entry.target.id}`) link.setAttribute("aria-current", "true");
          else link.removeAttribute("aria-current");
        }
      }
    },
    { rootMargin: "-45% 0px -50% 0px" },
  );
  targets.forEach((target) => observer.observe(target));
}

function navMenu() {
  const menu = document.getElementById("site-menu");
  if (!menu || typeof menu.hidePopover !== "function") return;

  menu.addEventListener("click", (event) => {
    if (event.target.closest("a") && menu.matches(":popover-open")) menu.hidePopover();
  });
}

function copyEmail() {
  const button = document.querySelector("[data-copy]");
  const status = document.querySelector("[data-copied]");
  if (!button || !status || !navigator.clipboard) return;

  button.hidden = false;

  let timer;
  const announce = (message) => {
    status.textContent = message;
    clearTimeout(timer);
    timer = setTimeout(() => (status.textContent = ""), 2500);
  };

  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(button.dataset.copy);
      announce("Email address copied to clipboard");
    } catch {
      announce("Copy failed. Select the address instead");
    }
  });
}

function particles() {
  const canvas = document.querySelector("[data-particles]");
  if (!canvas || !canvas.getContext) return;

  const ctx = canvas.getContext("2d");
  const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const logo = new Image();
  let dots = [];
  let width = 0;
  let height = 0;
  let lastScroll = scrollY;
  let kick = 0;

  const build = () => {
    const ratio = Math.min(devicePixelRatio || 1, 2);
    width = innerWidth;
    height = innerHeight;
    canvas.width = width * ratio;
    canvas.height = height * ratio;
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);

    const w = Math.round(Math.min(width * 0.78, 960));
    const h = Math.round((w * logo.naturalHeight) / logo.naturalWidth);
    const sample = document.createElement("canvas");
    sample.width = w;
    sample.height = h;
    const sctx = sample.getContext("2d", { willReadFrequently: true });
    sctx.drawImage(logo, 0, 0, w, h);
    const pixels = sctx.getImageData(0, 0, w, h).data;

    const step = Math.max(4, Math.round(w / 150));
    const left = (width - w) / 2;
    const top = (height - h) / 2;
    dots = [];
    for (let y = 0; y < h; y += step) {
      for (let x = 0; x < w; x += step) {
        if (pixels[((y * w) + x) * 4 + 3] < 128) continue;
        const depth = 0.3 + Math.random() * 0.7;
        dots.push({
          hx: left + x + (Math.random() - 0.5) * step,
          hy: top + y + (Math.random() - 0.5) * step,
          ox: 0,
          oy: 0,
          vx: 0,
          vy: 0,
          depth,
          phase: Math.random() * Math.PI * 2,
          size: 0.7 + depth * 0.9,
        });
      }
    }
  };

  const draw = (time) => {
    ctx.clearRect(0, 0, width, height);
    ctx.fillStyle = "#fff";
    for (const dot of dots) {
      const speed = Math.hypot(dot.vx, dot.vy);
      const drift = still ? 0 : Math.sin(time / 2600 + dot.phase) * 1.6 * dot.depth;
      ctx.globalAlpha = Math.min(0.14 + dot.depth * 0.14 + speed * 0.05, 0.6);
      ctx.fillRect(dot.hx + dot.ox + drift, dot.hy + dot.oy - drift, dot.size, dot.size);
    }
  };

  const FRAME = 1000 / 60;
  let previous = 0;
  let owed = 0;

  const step = (time) => {
    owed = Math.min(owed + (previous ? time - previous : FRAME), FRAME * 4);
    previous = time;
    while (owed >= FRAME) {
      owed -= FRAME;
      kick *= 0.85;
      for (const dot of dots) {
        dot.vx += (Math.random() - 0.5) * Math.abs(kick) * 0.04 * dot.depth - dot.ox * 0.018;
        dot.vy += -kick * dot.depth * 0.09 - dot.oy * 0.018;
        dot.vx *= 0.92;
        dot.vy *= 0.92;
        dot.ox += dot.vx;
        dot.oy += dot.vy;
      }
    }
    draw(time);
    requestAnimationFrame(step);
  };

  addEventListener("scroll", () => {
    const delta = scrollY - lastScroll;
    lastScroll = scrollY;
    kick = Math.max(-60, Math.min(60, kick + delta));
  }, { passive: true });

  let timer;
  addEventListener("resize", () => {
    clearTimeout(timer);
    timer = setTimeout(() => logo.naturalWidth && build(), 150);
  });

  logo.addEventListener("load", () => {
    build();
    if (still) draw(0);
    else requestAnimationFrame(step);
  });
  logo.src = canvas.dataset.src;
}

function lightbox() {
  const links = [...document.querySelectorAll("a[data-lightbox]")];
  if (!links.length || typeof HTMLDialogElement === "undefined") return;

  const dialog = document.createElement("dialog");
  dialog.className = "lightbox";
  dialog.setAttribute("aria-label", "Screenshot viewer");
  dialog.innerHTML =
    '<div class="lightbox-body"><img alt="">' +
    '<div class="lightbox-bar">' +
    '<button type="button" data-step="-1" aria-label="Previous screenshot">←</button>' +
    '<span class="lightbox-count mono" aria-live="polite"></span>' +
    '<button type="button" data-step="1" aria-label="Next screenshot">→</button>' +
    '<button type="button" data-close>Close</button>' +
    "</div></div>";
  document.body.append(dialog);

  const image = dialog.querySelector("img");
  const count = dialog.querySelector(".lightbox-count");
  const steppers = dialog.querySelectorAll("[data-step]");
  let current = 0;
  let opener = null;

  const show = (index) => {
    current = (index + links.length) % links.length;
    image.src = links[current].href;
    image.alt = links[current].querySelector("img")?.alt ?? "";
    count.textContent = `${current + 1} / ${links.length}`;
  };

  steppers.forEach((button) => (button.hidden = links.length < 2));

  for (const link of links) {
    link.addEventListener("click", (event) => {
      if (event.metaKey || event.ctrlKey || event.shiftKey || event.button) return;
      event.preventDefault();
      opener = link;
      show(links.indexOf(link));
      dialog.showModal();
    });
  }

  dialog.addEventListener("click", (event) => {
    const step = event.target.closest("[data-step]");
    if (step) show(current + Number(step.dataset.step));
    else if (event.target.closest("[data-close]") || !event.target.closest(".lightbox-body, button")) dialog.close();
  });

  dialog.addEventListener("keydown", (event) => {
    if (links.length < 2) return;
    if (event.key === "ArrowLeft") show(current - 1);
    if (event.key === "ArrowRight") show(current + 1);
  });

  dialog.addEventListener("close", () => opener?.focus());
}

for (const init of [activeSection, navMenu, copyEmail, particles, lightbox]) init();
