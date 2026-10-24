(function () {
    try {
        var saved = localStorage.getItem("goosko-theme");
        if (saved === "light" || saved === "dark") {
            document.documentElement.dataset.theme = saved;
        }
    } catch (error) {
        void error;
    }
})();
