
document.addEventListener("DOMContentLoaded", () => {
    initCyberParticleCanvas();
    initCharts();
});

/**
 * Red & Black SaaS Animated Particle Network Background
 */
function initCyberParticleCanvas() {
    const canvas = document.getElementById("cyberCanvas");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");

    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    window.addEventListener("resize", () => {
        width = canvas.width = window.innerWidth;
        height = canvas.height = window.innerHeight;
    });

    const particles = Array.from({ length: 55 }, () => ({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.45,
        vy: (Math.random() - 0.5) * 0.45,
        radius: Math.random() * 1.8 + 0.8
    }));

    function draw() {
        ctx.clearRect(0, 0, width, height);

        for (let i = 0; i < particles.length; i++) {
            const p = particles[i];
            p.x += p.vx;
            p.y += p.vy;

            if (p.x < 0 || p.x > width) p.vx *= -1;
            if (p.y < 0 || p.y > height) p.vy *= -1;

            ctx.beginPath();
            ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
            ctx.fillStyle = "rgba(255, 30, 66, 0.55)";
            ctx.fill();

            for (let j = i + 1; j < particles.length; j++) {
                const p2 = particles[j];
                const dist = Math.hypot(p.x - p2.x, p.y - p2.y);
                if (dist < 135) {
                    ctx.beginPath();
                    ctx.moveTo(p.x, p.y);
                    ctx.lineTo(p2.x, p2.y);
                    ctx.strokeStyle = `rgba(255, 30, 66, ${(1 - dist / 135) * 0.16})`;
                    ctx.lineWidth = 0.8;
                    ctx.stroke();
                }
            }
        }
        requestAnimationFrame(draw);
    }
    draw();
}

/**
 * Chart.js Visualizations for Severity & Category Telemetry
 */
function initCharts() {
    const telemetry = window.WEBVULNX_TELEMETRY || {
        severities: [0, 0, 0, 0, 0],
        categoryLabels: ["Headers", "XSS", "SQL", "IDOR", "Session"],
        categoryCounts: [0, 0, 0, 0, 0]
    };

    const sevCtx = document.getElementById("severityChart");
    if (sevCtx) {
        const totalSev = telemetry.severities.reduce((a, b) => a + b, 0);
        const displayData = totalSev > 0 ? telemetry.severities : [1, 1, 1, 1, 1];

        new Chart(sevCtx, {
            type: "doughnut",
            data: {
                labels: ["Critical", "High", "Medium", "Low", "Informational"],
                datasets: [{
                    data: displayData,
                    backgroundColor: [
                        "#ff1e42",
                        "#ff5722",
                        "#ffb300",
                        "#00e676",
                        "#29b6f6"
                    ],
                    borderColor: "#0a0a0f",
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: "72%",
                plugins: {
                    legend: {
                        position: "right",
                        labels: { color: "#d1d5db", font: { family: "Space Grotesk" } }
                    }
                }
            }
        });
    }

    const catCtx = document.getElementById("categoryChart");
    if (catCtx) {
        new Chart(catCtx, {
            type: "bar",
            data: {
                labels: telemetry.categoryLabels,
                datasets: [{
                    label: "Findings Count",
                    data: telemetry.categoryCounts,
                    backgroundColor: "rgba(255, 30, 66, 0.65)",
                    borderColor: "#ff1e42",
                    borderWidth: 1,
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { color: "#9ca3af", stepSize: 1 },
                        grid: { color: "rgba(255, 255, 255, 0.05)" }
                    },
                    x: {
                        ticks: { color: "#d1d5db" },
                        grid: { display: false }
                    }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
    }
}
