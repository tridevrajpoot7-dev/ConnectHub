/* =========================================
   CONNECTHUB - MAIN SCRIPT
========================================= */


/* =========================================
   SIGNUP
========================================= */

const signupForm =
    document.getElementById("signupForm");

if (signupForm) {

    signupForm.addEventListener(
        "submit",
        async function (event) {

            event.preventDefault();

            const name =
                document.getElementById("name").value.trim();

            const email =
                document.getElementById("email").value.trim();

            const password =
                document.getElementById("password").value;

            const age =
                document.getElementById("age").value;

            const selectedInterests =
                Array.from(
                    document.querySelectorAll(
                        '.interest-options input[type="checkbox"]:checked'
                    )
                ).map(function (checkbox) {
                    return checkbox.value;
                });


            try {

                const response =
                    await fetch("/api/signup", {

                        method: "POST",

                        headers: {
                            "Content-Type": "application/json"
                        },

                        body: JSON.stringify({

                            name,
                            email,
                            password,
                            age,
                            interests:
                                selectedInterests

                        })

                    });


                const data =
                    await response.json();


                if (!response.ok) {

                    alert(
                        data.message ||
                        "Account creation failed."
                    );

                    return;

                }


                /* SAVE USER ID */

                localStorage.setItem(
                    "userId",
                    data.user.id
                );

                localStorage.setItem(
                    "userName",
                    data.user.name
                );

                localStorage.setItem(
                    "userEmail",
                    data.user.email
                );

                localStorage.setItem(
                    "userAge",
                    data.user.age
                );

                localStorage.setItem(
                    "userInterests",
                    (data.user.interests || []).join(", ")
                );

                localStorage.setItem(
                    "userLoggedIn",
                    "true"
                );


                alert(
                    data.message ||
                    "Account created successfully! 🎉"
                );


                window.location.href =
                    "profile.html";

            } catch (error) {

                console.error(
                    "Signup error:",
                    error
                );

                alert(
                    "Server se connection nahi ho pa raha. " +
                    "Check karo ki Node server running hai."
                );

            }

        }
    );

}


/* =========================================
   LOGIN
========================================= */

const loginForm =
    document.getElementById("loginForm");

if (loginForm) {

    loginForm.addEventListener(
        "submit",
        async function (event) {

            event.preventDefault();


            const loginEmail =
                document.getElementById(
                    "loginEmail"
                ).value.trim();


            const loginPassword =
                document.getElementById(
                    "loginPassword"
                ).value;


            try {

                const response =
                    await fetch("/api/login", {

                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/json"
                        },

                        body: JSON.stringify({

                            email:
                                loginEmail,

                            password:
                                loginPassword

                        })

                    });


                const data =
                    await response.json();


                if (!response.ok) {

                    alert(
                        data.message ||
                        "Login failed."
                    );

                    return;

                }


                /* SAVE USER ID */

                localStorage.setItem(
                    "userId",
                    data.user.id
                );

                localStorage.setItem(
                    "userName",
                    data.user.name
                );

                localStorage.setItem(
                    "userEmail",
                    data.user.email
                );

                localStorage.setItem(
                    "userAge",
                    data.user.age
                );

                localStorage.setItem(
                    "userInterests",
                    (data.user.interests || []).join(", ")
                );

                localStorage.setItem(
                    "userLoggedIn",
                    "true"
                );


                alert(
                    data.message ||
                    "Login successful! 🎉"
                );


                window.location.href =
                    "profile.html";


            } catch (error) {

                console.error(
                    "Login error:",
                    error
                );

                alert(
                    "Server se connection nahi ho pa raha."
                );

            }

        }
    );

}


/* =========================================
   INDEX PAGE BUTTONS
========================================= */

const loginButton =
    document.querySelector(".login-btn");

const signupButton =
    document.querySelector(".signup-btn");


if (loginButton) {

    loginButton.addEventListener(
        "click",
        function () {

            window.location.href =
                "login.html";

        }
    );

}


if (signupButton) {

    signupButton.addEventListener(
        "click",
        function () {

            window.location.href =
                "signup.html";

        }
    );

}


/* =========================================
   GLOBAL NOTIFICATION BADGE
========================================= */

async function updateNotificationBadge() {

    const userId =
        localStorage.getItem("userId");


    /* User login nahi hai */

    if (!userId) {
        return;
    }


    const badge =
        document.getElementById(
            "notificationCount"
        );


    /* Is page par notification badge nahi hai */

    if (!badge) {
        return;
    }


    try {

        const response =
            await fetch(
                "/api/notifications/" +
                userId
            );


        const data =
            await response.json();


        if (
            !response.ok ||
            !data.success
        ) {
            return;
        }


        const notifications =
            data.notifications || [];


        /* COUNT UNREAD */

        const unreadCount =
            notifications.filter(
                function (notification) {
                    return !notification.read;
                }
            ).length;


        /* SHOW BADGE */

        if (unreadCount > 0) {

            badge.textContent =
                unreadCount > 99
                    ? "99+"
                    : unreadCount;

            badge.className =
                "notification-count";

        } else {

            badge.textContent =
                "";

            badge.className =
                "";

        }


    } catch (error) {

        console.error(
            "Notification badge error:",
            error
        );

    }

}


/* =========================================
   UPDATE BADGE NOW
========================================= */

updateNotificationBadge();


/* =========================================
   CHECK NEW NOTIFICATIONS EVERY 5 SECONDS
========================================= */

setInterval(
    updateNotificationBadge,
    5000
);