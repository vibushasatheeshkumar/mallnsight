/* ==========================================
   MallnSight UI
========================================== */

document.addEventListener("DOMContentLoaded", () => {

    /* ===========================
       Navbar Scroll Effect
    =========================== */

    const navbar = document.querySelector(".navbar");

    window.addEventListener("scroll", () => {

        if (window.scrollY > 40) {

            navbar.style.background = "rgba(13,17,23,.97)";
            navbar.style.boxShadow = "0 8px 25px rgba(0,0,0,.35)";

        } else {

            navbar.style.background = "rgba(13,17,23,.90)";
            navbar.style.boxShadow = "none";

        }

    });

    /* ===========================
       Reveal Animation
    =========================== */

    const reveals = document.querySelectorAll(
        ".feature-card,.workflow-step,.cta,.hero-image,.section-title," +
        ".doc-block,.contact-card"
    );

    const observer = new IntersectionObserver((entries)=>{

        entries.forEach(entry=>{

            if(entry.isIntersecting){

                entry.target.style.opacity="1";
                entry.target.style.transform="translateY(0px)";

                observer.unobserve(entry.target);

            }

        });

    },{

        threshold:0.15

    });

    reveals.forEach((item,index)=>{

        item.style.opacity="0";
        item.style.transform="translateY(40px)";
        item.style.transition=`opacity .6s cubic-bezier(.16,1,.3,1) ${(index%3)*0.08}s,
                                transform .6s cubic-bezier(.16,1,.3,1) ${(index%3)*0.08}s`;

        observer.observe(item);

    });

    /* ===========================
       Card Hover Tilt
    =========================== */

    document.querySelectorAll(".feature-card").forEach(card=>{

        card.addEventListener("mousemove",(e)=>{

            const rect = card.getBoundingClientRect();

            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;

            const rotateX = (y - rect.height/2)/25;
            const rotateY = -(x - rect.width/2)/25;

            card.style.transform=
                `perspective(800px)
                rotateX(${rotateX}deg)
                rotateY(${rotateY}deg)
                translateY(-6px)`;

        });

        card.addEventListener("mouseleave",()=>{

            card.style.transform="translateY(0px)";

        });

    });

    /* ===========================
       Hero Icon Pulse
    =========================== */

    const heroIcon = document.querySelector(".hero-image i");

    if(heroIcon){

        setInterval(()=>{

            heroIcon.animate([

                {
                    transform:"scale(1)"
                },

                {
                    transform:"scale(1.08)"
                },

                {
                    transform:"scale(1)"
                }

            ],{

                duration:1800

            });

        },3500);

    }

});