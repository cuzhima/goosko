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
            }
        });

        input.addEventListener("change", () => {
            const label = dropzone.querySelector("[data-file-name]");
            if (label && input.files.length) {
                label.textContent = input.files[0].name;
            }
        });
    });

    // Прогресс загрузки файла
    document.querySelectorAll("form[data-upload-progress]").forEach((form) => {
        const progress = form.querySelector(".progress");
        const fill = progress?.querySelector("span");

        if (!progress || !fill) return;

        form.addEventListener("submit", (event) => {
            event.preventDefault();

            const formData = new FormData(form);
            const xhr = new XMLHttpRequest();

            xhr.open(form.method || "POST", form.action || window.location.href);
            xhr.timeout = 0;

            xhr.upload.onprogress = (event) => {
                if (event.lengthComputable) {
                    progress.hidden = false;
                    const percent = Math.round((event.loaded / event.total) * 100);
                    fill.style.width = percent + "%";
                }
            };

            xhr.onload = () => {
                if (xhr.status >= 200 && xhr.status < 400) {
                    if (form.dataset.redirect) {
                        window.location.href = form.dataset.redirect;
                    } else {
                        alert("✅ Загружено");
                        progress.hidden = true;
                        fill.style.width = "0";
                        form.reset();
                    }
                } else {
                    alert("Ошибка загрузки: " + (xhr.responseText || xhr.status));
                }
            };

            xhr.onerror = () => {
                alert("Ошибка сети при загрузке файла");
            };

            xhr.send(formData);
        });
    });
});