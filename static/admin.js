// Админ-панель: снимок с веб-камеры.
(function () {
    const csrfMeta = document.querySelector('meta[name="csrf-token"]');
    const csrf = csrfMeta ? csrfMeta.content : "";

    const btn = document.getElementById("webcam-shot-btn");
    const box = document.getElementById("webcam-shot-box");
    const img = document.getElementById("webcam-shot-img");
    if (!btn) return;

    function toast(message, type) {
        if (typeof showToast === "function") showToast(message, type || "info");
        else alert(message);
    }

    btn.addEventListener("click", async () => {
        if (btn.disabled) return;
        btn.disabled = true;
        const original = btn.textContent;
        btn.textContent = "Снимаем…";
        try {
            const response = await fetch("/admin/webcam", {
                method: "POST",
                credentials: "same-origin",
                headers: { "X-CSRFToken": csrf },
            });
            const data = await response.json();
            if (data.ok && data.url) {
                img.src = data.url;
                box.hidden = false;
                toast("📸 Снимок готов", "ok");
            } else {
                toast("Не удалось: " + (data.message || "ошибка камеры"), "error");
            }
        } catch (error) {
            toast("Не удалось сделать снимок", "error");
        } finally {
            btn.disabled = false;
            btn.textContent = original;
        }
    });
})();
