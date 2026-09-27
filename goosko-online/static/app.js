function formatSize(bytes) {
    if (!bytes || bytes < 0) return "0 Б";
    const units = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
    let i = 0;
    let value = bytes;
    while (value >= 1024 && i < units.length - 1) {
        value /= 1024;
        i += 1;
    }
    return (i === 0 ? value : value.toFixed(1)) + " " + units[i];
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

document.addEventListener("DOMContentLoaded", () => {
    initProgressBars();

    // Переключатель тёмной темы (выбор сохраняется в localStorage)
    const themeBtn = document.getElementById("theme-toggle");
    if (themeBtn) {
        const syncLabel = () => {
            themeBtn.textContent =
                document.documentElement.classList.contains("dark") ? "☀️" : "🌙";
        };
        themeBtn.addEventListener("click", () => {
            const dark = document.documentElement.classList.toggle("dark");
            try { localStorage.setItem("theme", dark ? "dark" : "light"); } catch (e) {}
            syncLabel();
        });
        syncLabel();
    }

    // Копирование в буфер обмена
    document.addEventListener("click", async (event) => {
        const button = event.target.closest("[data-copy]");
        if (!button) return;

        event.preventDefault();

        const text = button.dataset.copy;

        try {
            await navigator.clipboard.writeText(text);
            const old = button.textContent;
            button.textContent = "✅ Скопировано";

            setTimeout(() => {
                button.textContent = old;
            }, 1500);
        } catch (error) {
            alert("Скопируйте ссылку вручную: " + text);
        }
    });

    // Подтверждение опасных действий
    document.addEventListener("submit", (event) => {
        const form = event.target.closest("form[data-confirm]");
        if (!form) return;

        const message = form.dataset.confirm || "Подтвердить действие?";

        if (!confirm(message)) {
            event.preventDefault();
        }
    });

    // Drag and drop для загрузки файлов
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
            if (!label) return;
            if (input.files.length === 0) {
                label.textContent = "Файлы не выбраны";
            } else if (input.files.length === 1) {
                label.textContent = input.files[0].name;
            } else {
                let total = 0;
                for (const f of input.files) total += f.size;
                label.textContent = `Выбрано файлов: ${input.files.length} (${formatSize(total)})`;
            }
        });
    });

    // Множественная загрузка через fetch с общим прогрессом
    document.querySelectorAll("form[data-upload-progress]").forEach((form) => {
        const progress = form.querySelector(".progress");
        const fill = progress?.querySelector("span");
        const input = form.querySelector("input[type=file]");
        if (!progress || !fill || !input) return;

        form.addEventListener("submit", async (event) => {
            event.preventDefault();

            const files = Array.from(input.files || []);
            if (files.length === 0) {
                alert("Сначала выбери файл");
                return;
            }

            const submitBtn = form.querySelector("button[type=submit]");
            if (submitBtn) submitBtn.disabled = true;
            progress.hidden = false;
            fill.style.width = "0%";

            const setProgress = (percent, label) => {
                fill.style.width = Math.round(percent) + "%";
                if (label) fill.textContent = label;
            };

            // Один запрос со всеми файлами, если сервер поддерживает API
            try {
                const totalBytes = files.reduce((s, f) => s + f.size, 0);
                const formData = new FormData(form);
                formData.delete("file");
                for (const f of files) formData.append("files", f);

                const xhr = new XMLHttpRequest();
                xhr.open("POST", "/cloud/upload-multi", true);
                xhr.timeout = 0;

                xhr.upload.onprogress = (e) => {
                    if (e.lengthComputable) {
                        setProgress(
                            (e.loaded / e.total) * 100,
                            `${formatSize(e.loaded)} / ${formatSize(totalBytes)}`
                        );
                    }
                };

                xhr.onload = () => {
                    let result = null;
                    try { result = JSON.parse(xhr.responseText); } catch (_) {}

                    if (result && Array.isArray(result.ok)) {
                        const errs = result.errors || [];
                        if (result.ok.length) {
                            setProgress(100, `Загружено: ${result.ok.length}`);
                        }
                        const msg =
                            `✅ Загружено файлов: ${result.ok.length}` +
                            (errs.length ? `\n❌ Ошибки:\n${errs.join("\n")}` : "");
                        alert(msg);
                        window.location.href = form.dataset.redirect || "/cloud";
                    } else if (xhr.status >= 200 && xhr.status < 400) {
                        window.location.href = form.dataset.redirect || "/cloud";
                    } else {
                        alert("Ошибка загрузки: " + (xhr.responseText || xhr.status));
                        progress.hidden = true;
                        if (submitBtn) submitBtn.disabled = false;
                    }
                };

                xhr.onerror = () => {
                    alert("Ошибка сети при загрузке файлов");
                    progress.hidden = true;
                    if (submitBtn) submitBtn.disabled = false;
                };

                xhr.send(formData);
            } catch (error) {
                alert("Ошибка: " + error.message);
                progress.hidden = true;
                if (submitBtn) submitBtn.disabled = false;
            }
        });
    });
});


// --- Быстрый доступ: подтверждение опасных действий питанием ---
document.addEventListener("submit", (event) => {
    const form = event.target.closest("form[data-confirm-power]");
    if (!form) return;

    const phrase = form.dataset.confirmPower || "";
    const value = (form.querySelector("input[name=confirm]")?.value || "").trim();

    if (value !== phrase) {
        event.preventDefault();
        alert("Введите точную фразу подтверждения: " + phrase);
        return;
    }

    if (!confirm("Точно выполнить это действие? Сервер может стать недоступен.")) {
        event.preventDefault();
    }
});
