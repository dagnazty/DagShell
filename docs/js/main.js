// DagShell Docs - Interactive JS

document.addEventListener('DOMContentLoaded', function() {
    // FAQ Toggle
    const faqItems = document.querySelectorAll('.faq-item');
    faqItems.forEach(item => {
        const question = item.querySelector('.faq-question');
        question.addEventListener('click', () => {
            item.classList.toggle('open');
        });
    });

    // Typing effect for hero text
    const typingElements = document.querySelectorAll('.typing');
    typingElements.forEach(el => {
        const text = el.textContent;
        el.textContent = '';
        let i = 0;
        const typeWriter = () => {
            if (i < text.length) {
                el.textContent += text.charAt(i);
                i++;
                setTimeout(typeWriter, 50);
            }
        };
        typeWriter();
    });

    // Smooth scroll for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({ behavior: 'smooth' });
            }
        });
    });

    // Add hover sound effect simulation (visual feedback)
    const navLinks = document.querySelectorAll('.nav a');
    navLinks.forEach(link => {
        link.addEventListener('mouseenter', () => {
            link.style.transition = 'all 0.1s';
        });
    });

    // Console easter egg
    console.log(`
 ____             ____  _          _ _ 
|  _ \\  __ _  __ / ___|| |__   ___| | |
| | | |/ _\` |/ _\\___ \\| '_ \\ / _ \\ | |
| |_| | (_| | (_| |__) | | | |  __/ | |
|____/ \\__,_|\\__, |___/|_| |_|\\___|_|_|
             |___/                     

Welcome to DagShell Documentation!
https://github.com/dagnazty/DagShell
    `);
});
