(function () {
    const csrfMeta = document.querySelector('meta[name="csrf-token"]');
    const csrf = csrfMeta ? csrfMeta.content : "";
    const byId = (id) => document.getElementById(id);

    function toast(message, type) {
        if (typeof showToast === "function") {
            showToast(message, type || "info");
        } else {
            console.log(message);
        }
    }

    function setText(id, value) {
        const el = byId(id);
        if (!el) return;
        el.textContent = value === null || value === undefined || value === ""
            ? "—"
            : String(value);
    }

    function tempClass(value) {
        if (value === null || value === undefined) return "";
        if (value >= 85) return "temp-crit";
        if (value >= 75) return "temp-warn";
        return "temp-ok";
    }

    function setTemp(id, value) {
        const el = byId(id);
        if (!el) return;
        el.textContent = value === null || value === undefined ? "—" : value + " °C";
        el.classList.remove("temp-ok", "temp-warn", "temp-crit");
        const cls = tempClass(value);
        if (cls) el.classList.add(cls);
    }

    function fmt(value) {
        if (value === null || value === undefined) return "—";
        const number = Number(value);
        if (Number.isNaN(number)) return String(value);
        return number.toLocaleString("ru-RU");
    }

    function thermalLabel(value) {
        return {
            normal: "норма",
            hot: "нагрев",
            critical: "критично",
            unknown: "нет данных",
        }[value] || value || "—";
    }

    function render(data) {
        const cpu = data.cpu || {};
        const disk = data.disk || {};
        const display = data.display || {};

        setTemp("cpu-temp", cpu.temp);
        setTemp("disk-temp", disk.temp);
        setText("cpu-thermal", thermalLabel(cpu.thermal));
        setText("cpu-freq", cpu.freq_mhz ? cpu.freq_mhz + " МГц" : "—");
        setText("cpu-max", cpu.max_mhz ? "макс. " + cpu.max_mhz + " МГц" : "");
        setText("cpu-load", cpu.load1);
        setText("cpu-model", cpu.model);
        setText("cpu-governor", cpu.governor);
        setText("cpu-epp", cpu.epp);
        setText("cpu-turbo", cpu.no_turbo === 1 ? "выключен" : cpu.no_turbo === 0 ? "включён" : "—");
        setText("cpu-profile", cpu.profile);
        setText("thermal-state", thermalLabel(cpu.thermal));

        setText("disk-dev", disk.dev);
        setText("disk-model", disk.model);
        setText("disk-model-short", disk.model);
        setText("disk-cycles", fmt(disk.load_cycles));
        setText("disk-hours", disk.power_on_hours ? fmt(disk.power_on_hours) + " ч" : "—");
        setText("disk-apm", disk.apm);
        setText("disk-sched", disk.scheduler);
        setText(
            "disk-smart",
            disk.smart_status === true ? "PASSED"
                : disk.smart_status === false ? "FAILED"
                : "—"
        );

        setText("display-state", display.lightdm === "active" ? "включён" : "выключен");
        const backlight = (display.backlight || [])[0];
        setText(
            "display-brightness",
            backlight ? backlight.percent + "% (" + backlight.brightness + "/" + backlight.max + ")" : "—"
        );
        const range = byId("brightness-range");
        if (range && backlight) range.value = backlight.percent;

        const funnel = data.funnel || {};
        setText("funnel-state", funnel.on ? "включён" : "выключен");
        const funnelUrl = byId("funnel-url");
        if (funnelUrl) funnelUrl.textContent = funnel.on && funnel.url ? funnel.url + "/" : "";

        const config = data.config || {};
        if (config.high_temp || config.critical_temp) {
            setText(
                "thermal-thresholds",
                "Пороги: " + (config.high_temp || "—") + " °C / " +
                (config.critical_temp || "—") + " °C, возврат при " +
                (config.resume_temp || "—") + " °C"
            );
        } else {
            setText("thermal-thresholds", "Пороги: —");
        }

        const stale = byId("sys-stale");
        if (stale) stale.hidden = !data.stale;
        const helpers = data.helpers || {};
        const missing = byId("sys-helpers");
        if (missing) {
            missing.hidden = helpers.display && helpers.power && helpers.disk
                && helpers.funnel && helpers.powerctl && helpers.webcam;
        }

        setText(
            "sys-updated",
            data.updated
                ? new Date(data.updated * 1000).toLocaleTimeString("ru-RU")
                : "нет данных"
        );
        setText(
            "sys-clock",
            data.server_time
                ? new Date(data.server_time * 1000).toLocaleTimeString("ru-RU")
                : "—"
        );
    }

    async function refresh() {
        try {
            const response = await fetch("/system/status", {
                credentials: "same-origin",
                headers: { Accept: "application/json" },
            });
            if (!response.ok) throw new Error("HTTP " + response.status);
            render(await response.json());
        } catch (error) {
            void error;
        }
    }

    async function action(name, value) {
        const payload = { action: name };
        if (value !== undefined) payload.value = value;

        const response = await fetch("/system/action", {
            method: "POST",
            credentials: "same-origin",
            headers: {
                "Content-Type": "application/json",
                "X-CSRFToken": csrf,
                Accept: "application/json",
            },
            body: JSON.stringify(payload),
        });

        let data = null;
        try {
            data = await response.json();
        } catch (error) {
            void error;
        }

        const ok = response.ok && data && data.ok;
        const message = (data && data.message) || ("HTTP " + response.status);
        toast(message, ok ? "ok" : "error");
        if (ok) setTimeout(refresh, 600);
    }

    document.addEventListener("click", async (event) => {
        const button = event.target.closest("[data-system-action]");
        if (!button) return;

        event.preventDefault();
        const name = button.dataset.systemAction;
        if (name === "display_off" && !confirm("Выключить экран? Сервер продолжит работать.")) {
            return;
        }

        button.disabled = true;
        try {
            await action(name);
        } catch (error) {
            void error;
            toast("Не удалось выполнить команду", "error");
        } finally {
            button.disabled = false;
        }
    });

    const applyBrightness = byId("brightness-apply");
    if (applyBrightness) {
        applyBrightness.addEventListener("click", async () => {
            const range = byId("brightness-range");
            if (!range) return;
            applyBrightness.disabled = true;
            try {
                await action("brightness", parseInt(range.value, 10));
            } catch (error) {
                void error;
                toast("Не удалось изменить яркость", "error");
            } finally {
                applyBrightness.disabled = false;
            }
        });
    }

    // ===== Веб-камера =====
    const shotBtn = byId("webcam-shot-btn");
    const shotBox = byId("webcam-shot-box");
    const shotImg = byId("webcam-shot-img");
    if (shotBtn) {
        shotBtn.addEventListener("click", async () => {
            if (shotBtn.disabled) return;
            shotBtn.disabled = true;
            const original = shotBtn.textContent;
            shotBtn.textContent = "Снимаем…";
            try {
                const response = await fetch("/admin/webcam", {
                    method: "POST",
                    credentials: "same-origin",
                    headers: { "X-CSRFToken": csrf },
                });
                const data = await response.json();
                if (data.ok && data.url) {
                    shotImg.src = data.url;
                    shotBox.hidden = false;
                    toast("📸 Снимок готов", "ok");
                } else {
                    toast("Не удалось: " + (data.message || "ошибка камеры"), "error");
                }
            } catch (error) {
                toast("Не удалось сделать снимок", "error");
            } finally {
                shotBtn.disabled = false;
                shotBtn.textContent = original;
            }
        });
    }

    refresh();
    setInterval(refresh, 10000);
})();
