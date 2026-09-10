const colorPreference = window.matchMedia('(prefers-color-scheme: dark)');
function applyTheme() { document.documentElement.dataset.bsTheme = colorPreference.matches ? 'dark' : 'light'; }
applyTheme();
colorPreference.addEventListener('change', applyTheme);
