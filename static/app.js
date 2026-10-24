const THEME_KEY = "goosko-theme";

function showToast(message, type = "info", timeout = 4000) {
    const stack = document.getElementById("toast-stack");
    if (!stack) {
        alert(message);
        return;
    }

    const toast = document.createElement("div");
    toast.className = "toast " + type;
    toast.textContent = message;
    stack.appendChild(toast);

    requestAnimationFrame(() => toast.classList.add("show"));

    const remove = () => {
        toast.classList.remove("show");
        setTimeout(() => toast.remove(), 250);
    };

    toast.addEventListener("click", remove);
    setTimeout(remove, timeout);
}

function initFlashMessages() {
    document.querySelectorAll(".flash").forEach((flash) => {
        flash.addEventListener("click", () => flash.remove());
        setTimeout(() => {
            flash.classList.add("fade-out");
            setTimeout(() => flash.remove(), 300);
        }, 8000);
    });
}

function systemTheme() {
    return window.matchMedia("(prefers-color-scheme: dark)").matches
        ? "dark"
        : "light";
}

function currentTheme() {
    return document.documentElement.dataset.theme || systemTheme();
}

function updateThemeIcon() {
    const icon = document.querySelector("[data-theme-icon]");
    if (!icon) return;
    icon.textContent = currentTheme() === "dark" ? "☀️" : "🌙";
}

function setTheme(theme) {
    if (theme === "system") {
        delete document.documentElement.dataset.theme;
        try {
            localStorage.removeItem(THEME_KEY);
        } catch (error) {
            void error;
        }
    } else {
        document.documentElement.dataset.theme = theme;
        try {
            localStorage.setItem(THEME_KEY, theme);
        } catch (error) {
            void error;
        }
    }
    updateThemeIcon();
}

function initTheme() {
    updateThemeIcon();

    const button = document.querySelector("[data-theme-toggle]");
    if (button) {
        button.addEventListener("click", () => {
            setTheme(currentTheme() === "dark" ? "light" : "dark");
        });
    }

    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => {
        if (!document.documentElement.dataset.theme) {
            updateThemeIcon();
        }
    };

    if (media.addEventListener) {
        media.addEventListener("change", onChange);
    } else if (media.addListener) {
        media.addListener(onChange);
    }
}

function initProgressBars() {
    document.querySelectorAll("[data-progress]").forEach((el) => {
        const span = el.querySelector("span");
        if (!span) return;

        let value = parseInt(el.dataset.progress || "0", 10);

        if (isNaN(value)) value = 0;
        if (value < 0) value = 0;
        if (value > 100) value = 100;

        span.style.width = value + "%";
    });
}

function initCopyButtons() {
    document.addEventListener("click", async (event) => {
        const button = event.target.closest("[data-copy]");
        if (!button) return;

        event.preventDefault();

        const text = button.dataset.copy;

        try {
            await navigator.clipboard.writeText(text);
            const old = button.textContent;
            button.textContent = "✅ Скопировано";
            showToast("Скопировано в буфер обмена", "ok", 1800);

            setTimeout(() => {
                button.textContent = old;
            }, 1500);
        } catch (error) {
            void error;
            showToast("Не удалось скопировать. Скопируйте вручную: " + text, "error", 7000);
        }
    });
}

function initConfirmForms() {
    document.addEventListener("submit", (event) => {
        const form = event.target.closest("form[data-confirm]");
        if (!form) return;

        const message = form.dataset.confirm || "Подтвердить действие?";

        if (!confirm(message)) {
            event.preventDefault();
        }
    });
}

function initFileDrop() {
    document.querySelectorAll("[data-file-drop]").forEach((dropzone) => {
        const input = dropzone.querySelector("input[type=file]");
        if (!input) return;

        ["dragenter", "dragover"].forEach((eventName) => {
            dropzone.addEventListener(eventName, (event) => {
                event.preventDefault();
                dropzone.classList.add("drag");
            });
        });

        ["dragleave", "drop"].forEach((eventName) => {
            dropzone.addEventListener(eventName, (event) => {
                event.preventDefault();
                dropzone.classList.remove("drag");
            });
        });

        dropzone.addEventListener("drop", (event) => {
            if (event.dataTransfer.files.length) {
                input.files = event.dataTransfer.files;
                input.dispatchEvent(new Event("change"));
            }
        });

        input.addEventListener("change", () => {
            const label = dropzone.querySelector("[data-file-name]");
            if (label && input.files.length) {
                label.textContent = input.files[0].name;
            }
        });
    });
}

function initUploads() {
    document.querySelectorAll("form[data-upload-progress]").forEach((form) => {
        const progress = form.querySelector(".progress");
        const fill = progress?.querySelector("span");

        if (!progress || !fill) return;

        form.addEventListener("submit", (event) => {
            event.preventDefault();

            const button = form.querySelector("button[type=submit]");
            const oldText = button ? button.textContent : "";

            if (button) {
                button.disabled = true;
                button.textContent = "⏳ Загрузка…";
            }

            const formData = new FormData(form);
            const xhr = new XMLHttpRequest();

            xhr.open(form.method || "POST", form.action || window.location.href);
            xhr.timeout = 0;

            xhr.upload.onprogress = (uploadEvent) => {
                if (uploadEvent.lengthComputable) {
                    progress.hidden = false;
                    const percent = Math.round(
                        (uploadEvent.loaded / uploadEvent.total) * 100
                    );
                    fill.style.width = percent + "%";
                }
            };

            xhr.onload = () => {
                if (button) {
                    button.disabled = false;
                    button.textContent = oldText;
                }

                if (xhr.status >= 200 && xhr.status < 400) {
                    if (form.dataset.redirect) {
                        window.location.href = form.dataset.redirect;
                    } else {
                        showToast("Файл загружен", "ok");
                        progress.hidden = true;
                        fill.style.width = "0";
                        form.reset();
                    }
                } else {
                    let message = xhr.responseText || "HTTP " + xhr.status;
                    message = message.replace(/<[^>]*>/g, " ").trim().slice(0, 300);
                    showToast("Ошибка загрузки: " + message, "error", 8000);
                    progress.hidden = true;
                    fill.style.width = "0";
                }
            };

            xhr.onerror = () => {
                if (button) {
                    button.disabled = false;
                    button.textContent = oldText;
                }
                showToast("Ошибка сети при загрузке файла", "error");
            };

            xhr.ontimeout = () => {
                if (button) {
                    button.disabled = false;
                    button.textContent = oldText;
                }
                showToast("Время загрузки истекло", "error");
            };

            xhr.send(formData);
        });
    });
}

function initTextPreviews() {
    document.querySelectorAll("[data-preview-text]").forEach(async (el) => {
        const url = el.dataset.previewText;
        try {
            const response = await fetch(url, { credentials: "same-origin" });
            if (!response.ok) throw new Error("HTTP " + response.status);
            const text = await response.text();
            const limit = 500000;
            el.textContent = text.length > limit
                ? text.slice(0, limit) + "\n\n… файл показан частично"
                : text;
        } catch (error) {
            void error;
            el.textContent = "Не удалось загрузить предпросмотр.";
        }
    });
}

function initRetryButtons() {
    document.querySelectorAll("[data-retry]").forEach((button) => {
        button.addEventListener("click", () => window.location.reload());
    });
}

function initServiceWorker() {
    if (!("serviceWorker" in navigator)) return;
    if (location.protocol !== "https:") return;

    window.addEventListener("load", () => {
        navigator.serviceWorker.register("/sw.js").catch(() => {});
    });
}

function initMobileMenu() {
    const toggle = document.querySelector("[data-menu-toggle]");
    const panel = document.getElementById("main-nav");
    if (!toggle || !panel) return;

    const setOpen = (open) => {
        panel.classList.toggle("open", open);
        toggle.setAttribute("aria-expanded", open ? "true" : "false");
        toggle.textContent = open ? "✕" : "☰";
    };

    toggle.addEventListener("click", () => {
        setOpen(!panel.classList.contains("open"));
    });

    panel.querySelectorAll("a").forEach((link) => {
        link.addEventListener("click", () => setOpen(false));
    });

    const desktop = window.matchMedia("(min-width: 721px)");
    const onChange = (event) => {
        if (event.matches) setOpen(false);
    };

    if (desktop.addEventListener) {
        desktop.addEventListener("change", onChange);
    } else if (desktop.addListener) {
        desktop.addListener(onChange);
    }
}

document.addEventListener("DOMContentLoaded", () => {
    initTheme();
    initMobileMenu();
    initFlashMessages();
    initProgressBars();
    initCopyButtons();
    initConfirmForms();
    initFileDrop();
    initUploads();
    initTextPreviews();
    initRetryButtons();
    initServiceWorker();
});
