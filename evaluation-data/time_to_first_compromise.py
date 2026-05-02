import matplotlib.pyplot as plt
import numpy as np

# -----------------------------
# Data
# -----------------------------
manual = [2.55, 6.23, 3.78]
cvss = [9.42, 5.15, 3.02]
ga = [1.68, 2.48, 1.67]

data = [manual, cvss, ga]
labels = ['Manual', 'CVSS', 'GA']

# -----------------------------
# Style
# -----------------------------
plt.style.use('seaborn-v0_8-whitegrid')
plt.rcParams.update({
    "font.size": 11,
    "axes.titlesize": 14,
    "axes.labelsize": 12
})

colors = ['#4C72B0', '#DD8452', '#55A868']


def main():
    fig, ax = plt.subplots(figsize=(9, 6))

    # -----------------------------
    # Boxplot
    # -----------------------------
    box = ax.boxplot(
        data,
        patch_artist=True,
        widths=0.5,
        showfliers=False
    )

    # Colour boxes
    for patch, color in zip(box['boxes'], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.4)

    # -----------------------------
    # Scatter (individual trials)
    # -----------------------------
    for i, (vals, color) in enumerate(zip(data, colors), start=1):
        x = np.random.normal(i, 0.04, size=len(vals))  # jitter
        ax.scatter(x, vals, color=color, s=40, zorder=3, edgecolor='white')

    # -----------------------------
    # Mean markers
    # -----------------------------
    means = [np.mean(d) for d in data]
    ax.scatter(range(1, 4), means,
               color='black', marker='D', s=20,
               label='Mean', zorder=4)

    # -----------------------------
    # Labels
    # -----------------------------
    ax.set_xticks(range(1, 4))
    ax.set_xticklabels(labels)

    ax.set_ylabel('Time to First Compromise (minutes)')
    ax.set_title('Time to First Compromise by Approach')

    # -----------------------------
    # Annotate mean values
    # -----------------------------
    for i, mean in enumerate(means, start=1):
        ax.text(i, mean + 0.3, f'{mean:.2f}',
                ha='center', fontsize=8, fontweight='bold')

    ax.legend()
    ax.set_ylim(0, max(cvss) * 1.15)

    plt.tight_layout()
    plt.savefig('time_to_first_compromise.png', dpi=300)
    plt.show()


if __name__ == "__main__":
    main()
