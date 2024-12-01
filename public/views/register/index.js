document.addEventListener("DOMContentLoaded", () => {
    const passwordInput = document.querySelector("#password");
    const clearIconPassword = document.querySelector("#clear-icon-password");

    passwordInput.addEventListener("input", () => {
        clearIconPassword.style.visibility = passwordInput.value ? "visible" : "hidden";
    });

    clearIconPassword.addEventListener("click", () => {
        passwordInput.value = "";
        clearIconPassword.style.visibility = "hidden";
    });

    const passwordAgainInput = document.querySelector("#password-again");
    const clearIconPasswordAgain = document.querySelector("#clear-icon-password-again");

    passwordAgainInput.addEventListener("input", () => {
        clearIconPasswordAgain.style.visibility = passwordAgainInput.value ? "visible" : "hidden";
    });

    clearIconPasswordAgain.addEventListener("click", () => {
        passwordAgainInput.value = "";
        clearIconPasswordAgain.style.visibility = "hidden";
    });
});
