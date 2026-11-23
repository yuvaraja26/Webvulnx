document.addEventListener("DOMContentLoaded", () => {
    bindCardSpotlights();
    animateMetricCounters();
    launchParticleField();
    renderTelemetryCharts();
});

function bindCardSpotlights() {
    document.querySelectorAll(".pro-card").forEach((card) => {
        card.addEventListener("mousemove", (e) => {
            const rect = card.getBoundingClientRect();
            const x = ((e.clientX - rect.left) / rect.width) * 100;
            const y = ((e.clientY - rect.top) / rect.height) * 100;
            card.style.setProperty("--mx", `${x}%`);
            card.style.setProperty("--my", `${y}%`);
        });
    });
}

function animateMetricCounters() {
    document.querySelectorAll("[data-countup]").forEach((el) => {
        const target = parseInt(el.getAttribute("data-countup"), 10) || 0;
        if (target === 0) {
            el.textContent = "0";
            return;
        }
        const duration = 850;
        const start = performance.now();

        function step(now) {
            const p = Math.min((now - start) / duration, 1);
            const eased = 1 - Math.pow(1 - p, 4);
            el.textContent = Math.round(eased * target).toString();
            if (p < 1) requestAnimationFrame(step);
        }
        requestAnimationFrame(step);
    });
}

function launchParticleField() {
    const canvas = document.getElementById("cyberCanvas");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");

    let w = (canvas.width = window.innerWidth);
    let h = (canvas.height = window.innerHeight);
    const mouse = { x: null, y: null };

    window.addEventListener("resize", () => {
        w = canvas.width = window.innerWidth;
        h = canvas.height = window.innerHeight;
    });
    window.addEventListener("mousemove", (e) => {
        mouse.x = e.clientX;
        mouse.y = e.clientY;
    });
    window.addEventListener("mouseleave", () => {
        mouse.x = null;
        mouse.y = null;
    });

    const total = Math.min(72, Math.floor((w * h) / 23000) + 30);
    const pts = Array.from({ length: total }, () => ({
        x: Math.random() * w,
        y: Math.random() * h,
        vx: (Math.random() - 0.5) * 0.36,
        vy: (Math.random() - 0.5) * 0.36,
        r: Math.random() * 1.75 + 0.7,
    }));

    function draw() {
        ctx.clearRect(0, 0, w, h);

        for (let i = 0; i < pts.length; i++) {
            const p = pts[i];
            p.x += p.vx;
            p.y += p.vy;

            if (p.x < 0 || p.x > w) p.vx *= -1;
            if (p.y < 0 || p.y > h) p.vy *= -1;

            if (mouse.x !== null && mouse.y !== null) {
                const dx = mouse.x - p.x;
                const dy = mouse.y - p.y;
                const d = Math.hypot(dx, dy);
                if (d < 145 && d > 1) {
                    p.x += (dx / d) * 0.36;
                    p.y += (dy / d) * 0.36;
                }
            }

            ctx.beginPath();
            ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
            ctx.fillStyle = "rgba(255, 23, 68, 0.58)";
            ctx.fill();

            for (let j = i + 1; j < pts.length; j++) {
                const q = pts[j];
                const dist = Math.hypot(p.x - q.x, p.y - q.y);
                if (dist < 135) {
                    ctx.beginPath();
                    ctx.moveTo(p.x, p.y);
                    ctx.lineTo(q.x, q.y);
                    ctx.strokeStyle = `rgba(255, 23, 68, ${(1 - dist / 135) * 0.15})`;
                    ctx.lineWidth = 0.85;
                    ctx.stroke();
                }
            }
        }
        requestAnimationFrame(draw);
    }
    draw();
}

function renderTelemetryCharts() {
    const data = window.WEBVULNX_TELEMETRY || {
        severities: [0, 0, 0, 0, 0],
        categoryLabels: ["Security Misconfiguration", "Information Disclosure", "Session Security"],
        categoryCounts: [0, 0, 0],
    };

    const sevEl = document.getElementById("severityChart");
    if (sevEl) {
        const total = data.severities.reduce((a, b) => a + b, 0);
        new Chart(sevEl, {
            type: "doughnut",
            data: {
                labels: ["Critical", "High", "Medium", "Low", "Informational"],
                datasets: [{
                    data: total > 0 ? data.severities : [1, 1, 1, 1, 1],
                    backgroundColor: ["#ff1744", "#f97316", "#f59e0b", "#10b981", "#38bdf8"],
                    borderColor: "#06060a",
                    borderWidth: 3,
                    hoverOffset: 7,
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

    const catEl = document.getElementById("categoryChart");
    if (catEl) {
        const ctx = catEl.getContext("2d");
        const grad = ctx.createLinearGradient(0, 0, 0, 260);
        grad.addColorStop(0, "rgba(255, 23, 68, 0.88)");
        grad.addColorStop(1, "rgba(110, 4, 24, 0.22)");

        new Chart(catEl, {
            type: "bar",
            data: {
                labels: data.categoryLabels,
                datasets: [{
                    label: "Findings",
                    data: data.categoryCounts,
                    backgroundColor: grad,
                    borderColor: "#ff5277",
                    borderWidth: 1.5,
                    borderRadius: 8,
                    maxBarThickness: 56,
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
