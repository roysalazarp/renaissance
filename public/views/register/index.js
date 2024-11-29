document.addEventListener("DOMContentLoaded", () => {
    const passwordInput = document.querySelector("#password");
    const passwordAgainInput = document.querySelector("#password-again");
    const clearIconPassword = document.querySelector("#clear-icon-password");
    const clearIconPasswordAgain = document.querySelector("#clear-icon-password-again");

    passwordInput.addEventListener("input", () => {
        clearIconPassword.style.visibility = passwordInput.value ? "visible" : "hidden";
    });

    clearIconPassword.addEventListener("click", () => {
        passwordInput.value = "";
        clearIconPassword.style.visibility = "hidden";
    });

    passwordAgainInput.addEventListener("input", () => {
        clearIconPasswordAgain.style.visibility = passwordAgainInput.value ? "visible" : "hidden";
    });

    clearIconPasswordAgain.addEventListener("click", () => {
        passwordAgainInput.value = "";
        clearIconPasswordAgain.style.visibility = "hidden";
    });
});
