import matplotlib.pyplot as plt
import numpy as np

# ---------------------------------------
# Assets and approaches
# ---------------------------------------
assets = [
    'DCS Admin',
    'PII Exfiltration',
    'Passenger Manifest',
    'Redis Access',
    'FIDS Admin',
    'DCS Database',
    'BHS RCE',
    'Boarding Pass Forgery'
]

approaches = ['Manual', 'CVSS', 'GA']

# ---------------------------------------
# Proportion of trials reached
# ---------------------------------------
data = np.array([
    [1.0, 1.0, 1.0],   # DCS Admin
    [1.0, 1.0, 1.0],   # PII
    [1.0, 1.0, 1.0],   # Manifest
    [1.0, 0.0, 1.0],   # Redis
    [0.67, 1.0, 1.0],  # FIDS
    [0.0, 0.0, 1.0],   # DCS DB
    [0.0, 0.0, 1.0],   # BHS RCE
    [0.0, 0.0, 0.0],   # Forgery
])


def main():
    fig, ax = plt.subplots(figsize=(8, 9))

    cmap = plt.cm.GnBu
    im = ax.imshow(data[::-1], cmap=cmap, vmin=0, vmax=1, aspect='auto')

    # ---------------------------------------
    # Annotate values
    # ---------------------------------------
    for i in range(data.shape[0]):
        for j in range(data.shape[1]):
            val = data[i, j]
            text = f'{int(val*100)}%'
            # Use white text on dark cells for readability
            text_color = 'white' if val > 0.6 else 'black'
            ax.text(j, data.shape[0]-1-i, text,
                    ha='center', va='center',
                    fontsize=11, fontweight='bold',
                    color=text_color)

    # ---------------------------------------
    # Axis labels
    # ---------------------------------------
    ax.set_xticks(np.arange(len(approaches)))
    ax.set_xticklabels(approaches, fontsize=12)
    ax.set_yticks(np.arange(len(assets)))
    ax.set_yticklabels(reversed(assets), fontsize=11)

    ax.xaxis.tick_top()
    ax.tick_params(length=0)

    cbar = plt.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    cbar.set_label('Proportion of Trials Reached', fontsize=11)

    # ---------------------------------------
    # Totals (mean coverage)
    # ---------------------------------------
    means = data.mean(axis=0)
    avg_y = -1.2

    for j, mean in enumerate(means):
        ax.text(j, avg_y, f'{mean*100:.0f}%',
                ha='center', va='center',
                fontsize=12, fontweight='bold')

    ax.text(-0.6, avg_y, 'Avg:',
            ha='right', va='center',
            fontsize=12, fontweight='bold')

    ax.set_ylim(len(assets) - 0.5, -1.6)

    ax.set_title('Critical Asset Coverage Consistency Across Approaches',
                 fontsize=14, fontweight='bold', pad=60)

    plt.tight_layout()
    plt.savefig('asset_coverage_heatmap.png',
                dpi=150, bbox_inches='tight')
    plt.show()


if __name__ == "__main__":
    main()
