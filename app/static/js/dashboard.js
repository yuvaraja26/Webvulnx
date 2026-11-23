document.addEventListener("DOMContentLoaded", () => {
    initSpotlightCards();
    initAnimatedCounters();
    initNeuralMeshCanvas();
    initTelemetryCharts();
});

/**
 * Cursor-following radial crimson spotlight on Bento cards
 */
function initSpotlightCards() {
    const cards = document.querySelectorAll(".bento-card");
    cards.forEach((card) => {
        card.addEventListener("mousemove", (e) => {
            const rect = card.getBoundingClientRect();
            const x = ((e.clientX - rect.left) / rect.width) * 100;
            const y = ((e.clientY - rect.top) / rect.height) * 100;
            card.style.setProperty("--mx", `${x}%`);
            card.style.setProperty("--my", `${y}%`);
        });
    });
}

/**
 * Smooth count-up animation for numeric KPIs and severity counters
 */
function initAnimatedCounters() {
    const counters = document.querySelectorAll("[data-countup]");
    counters.forEach((el) => {
        const target = parseInt(el.getAttribute("data-countup"), 10) || 0;
        if (target === 0) {
            el.textContent = "0";
            return;
        }
        const duration = 850;
        const startTime = performance.now();

        function tick(now) {
            const elapsed = now - startTime;
            const progress = Math.min(elapsed / duration, 1);
            const eased = 1 - Math.pow(1 - progress, 4);
            el.textContent = Math.round(eased * target).toString();
            if (progress < 1) {
                requestAnimationFrame(tick);
            }
        }
        requestAnimationFrame(tick);
    });
}

/**
 * Subtle interactive red/black particle network with pointer attraction
 */
function initNeuralMeshCanvas() {
    const canvas = document.getElementById("cyberCanvas");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");

    let w = (canvas.width = window.innerWidth);
    let h = (canvas.height = window.innerHeight);
    const pointer = { x: null, y: null };

    window.addEventListener("resize", () => {
        w = canvas.width = window.innerWidth;
        h = canvas.height = window.innerHeight;
    });

    window.addEventListener("mousemove", (e) => {
        pointer.x = e.clientX;
        pointer.y = e.clientY;
    });

    window.addEventListener("mouseleave", () => {
        pointer.x = null;
        pointer.y = null;
    });

    const count = Math.min(68, Math.floor((w * h) / 24000) + 28);
    const nodes = Array.from({ length: count }, () => ({
        x: Math.random() * w,
        y: Math.random() * h,
        vx: (Math.random() - 0.5) * 0.38,
        vy: (Math.random() - 0.5) * 0.38,
        r: Math.random() * 1.7 + 0.7,
    }));

    function frame() {
        ctx.clearRect(0, 0, w, h);

        for (let i = 0; i < nodes.length; i++) {
            const n = nodes[i];
            n.x += n.vx;
            n.y += n.vy;

            if (n.x < 0 || n.x > w) n.vx *= -1;
            if (n.y < 0 || n.y > h) n.vy *= -1;

            if (pointer.x !== null && pointer.y !== null) {
                const dx = pointer.x - n.x;
                const dy = pointer.y - n.y;
                const dist = Math.hypot(dx, dy);
                if (dist < 140 && dist > 1) {
                    n.x += (dx / dist) * 0.35;
                    n.y += (dy / dist) * 0.35;
                }
            }

            ctx.beginPath();
            ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
            ctx.fillStyle = "rgba(255, 23, 68, 0.55)";
            ctx.fill();

            for (let j = i + 1; j < nodes.length; j++) {
                const m = nodes[j];
                const d = Math.hypot(n.x - m.x, n.y - m.y);
                if (d < 130) {
                    ctx.beginPath();
                    ctx.moveTo(n.x, n.y);
                    ctx.lineTo(m.x, m.y);
                    ctx.strokeStyle = `rgba(255, 23, 68, ${(1 - d / 130) * 0.14})`;
                    ctx.lineWidth = 0.85;
                    ctx.stroke();
                }
            }
        }
        requestAnimationFrame(frame);
    }
    frame();
}

/**
 * Chart.js charts with red/black SaaS styling
 */
function initTelemetryCharts() {
    const telemetry = window.WEBVULNX_TELEMETRY || {
        severities: [0, 0, 0, 0, 0],
        categoryLabels: ["Security Misconfiguration", "Information Disclosure", "Session Security"],
        categoryCounts: [0, 0, 0],
    };

    const sevCanvas = document.getElementById("severityChart");
    if (sevCanvas) {
        const sum = telemetry.severities.reduce((a, b) => a + b, 0);
        const series = sum > 0 ? telemetry.severities : [0, 0, 0, 0, 0];

        new Chart(sevCanvas, {
            type: "doughnut",
            data: {
                labels: ["Critical", "High", "Medium", "Low", "Informational"],
                datasets: [{
                    data: sum > 0 ? series : [1, 1, 1, 1, 1],
                    backgroundColor: ["#ff1744", "#f97316", "#f59e0b", "#10b981", "#38bdf8"],
                    borderColor: "#09090d",
                    borderWidth: 3,
                    hoverOffset: 6,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: "74%",
                animation: { duration: 900 },
                plugins: {
                    legend: {
                        position: "right",
                        labels: {
                            color: "#cbd5e1",
                            padding: 14,
                            font: { family: "Plus Jakarta Sans", size: 12 },
                        },
                    },
                },
            },
        });
    }

    const catCanvas = document.getElementById("categoryChart");
    if (catCanvas) {
        const ctx2d = catCanvas.getContext("2d");
        const grad = ctx2d.createLinearGradient(0, 0, 0, 260);
        grad.addColorStop(0, "rgba(255, 23, 68, 0.85)");
        grad.addColorStop(1, "rgba(122, 4, 25, 0.22)");

        new Chart(catCanvas, {
            type: "bar",
            data: {
                labels: telemetry.categoryLabels,
                datasets: [{
                    label: "Findings",
                    data: telemetry.categoryCounts,
                    backgroundColor: grad,
                    borderColor: "#ff4569",
                    borderWidth: 1.5,
                    borderRadius: 8,
                    maxBarThickness: 54,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 900 },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { color: "#94a3b8", stepSize: 1, font: { family: "JetBrains Mono" } },
                        grid: { color: "rgba(255, 255, 255, 0.05)" },
                    },
                    x: {
                        ticks: { color: "#e2e8f0", font: { family: "Plus Jakarta Sans", size: 12 } },
                        grid: { display: false },
                    },
                },
                plugins: { legend: { display: false } },
            },
        });
    }
}
