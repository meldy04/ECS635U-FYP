import numpy as np
import matplotlib.pyplot as plt

END_TIME = 30
TIME_STEP = 0.5
time_grid = np.arange(0, END_TIME + TIME_STEP, TIME_STEP)


def minutes(mins, secs):
    return mins + secs / 60


# ---------------------------------------
# DATA POINTS PER TRIAL
# ---------------------------------------
manual_trials = [
    # Trial 1
    [
        (minutes(2, 33), 'DCS Info Disclosure'),
        (minutes(3, 29), 'Redis Access'),
        (minutes(5, 31), 'FIDS Admin'),
        (minutes(7, 56), 'Booking PII'),
        (minutes(10, 31), 'DCS Admin'),
        (minutes(15, 23), 'Manifest'),
    ],

    # Trial 2
    [
        (minutes(6, 14), 'FIDS Admin'),
        (minutes(8, 58), 'Booking PII'),
        (minutes(10, 22), 'DCS Info Disclosure'),
        (minutes(13, 0), 'DCS Admin'),
        (minutes(20, 56), 'Manifest'),
        (minutes(26, 30), 'Redis Access'),
    ],

    # Trial 3
    [
        (minutes(3, 47), 'DCS Info Disclosure'),
        (minutes(6, 55), 'Booking PII'),
        (minutes(11, 12), 'DCS Admin'),
        (minutes(12, 13), 'Manifest'),
        (minutes(19, 52), 'Redis Access'),
    ]
]

cvss_trials = [
    # Trial 1
    [
        (minutes(9, 25), 'Booking PII'),
        (minutes(18, 27), 'DCS Admin'),
        (minutes(21, 47), 'Manifest'),
        (minutes(24, 8), 'FIDS Admin'),
    ],

    # Trial 2
    [
        (minutes(5, 9), 'Booking PII'),
        (minutes(9, 29), 'DCS Admin'),
        (minutes(11, 24), 'Manifest'),
        (minutes(12, 10), 'FIDS Admin'),
    ],

    # Trial 3
    [
        (minutes(3, 1), 'Booking PII'),
        (minutes(7, 10), 'DCS Admin'),
        (minutes(9, 11), 'Manifest'),
        (minutes(11, 10), 'FIDS Admin'),
    ]
]

ga_trials = [
    # Trial 1
    [
        (minutes(1, 41), 'FIDS Admin'),
        (minutes(2, 17), 'DCS Info Disclosure'),
        (minutes(2, 37), 'Redis Access'),
        (minutes(4, 5), 'DCS Admin'),
        (minutes(4, 10), 'DCS Database'),
        (minutes(4, 54), 'Manifest'),
        (minutes(4, 54), 'Booking PII'),
        (minutes(24, 8), 'BHS RCE')
    ],

    # Trial 2
    [
        (minutes(2, 29), 'FIDS Admin'),
        (minutes(3, 10), 'DCS Info Disclosure'),
        (minutes(3, 47), 'Redis Access'),
        (minutes(5, 17), 'DCS Admin'),
        (minutes(5, 23), 'DCS Database'),
        (minutes(6, 19), 'Manifest'),
        (minutes(6, 19), 'Booking PII'),
        (minutes(19, 6), 'BHS RCE')
    ],

    # Trial 3
    [
        (minutes(1, 40), 'FIDS Admin'),
        (minutes(2, 26), 'DCS Info Disclosure'),
        (minutes(2, 51), 'Redis Access'),
        (minutes(4, 1), 'DCS Admin'),
        (minutes(4, 15), 'DCS Database'),
        (minutes(4, 40), 'Manifest'),
        (minutes(4, 40), 'Booking PII'),
        (minutes(22, 30), 'BHS RCE')
    ]
]


# ---------------------------------------
# Convert trial to cumulative curve
# ---------------------------------------
def trial_to_curve(events, time_grid):
    counts = []
    for t in time_grid:
        count = sum(1 for event_time, _ in events if event_time <= t)
        counts.append(count)
    return np.array(counts)


# ---------------------------------------
# Compute mean + std across trials
# ---------------------------------------
def compute_stats(trials):
    curves = np.array([trial_to_curve(t, time_grid) for t in trials])
    mean = curves.mean(axis=0)
    std = curves.std(axis=0)
    return mean, std


m_mean, m_std = compute_stats(manual_trials)
c_mean, c_std = compute_stats(cvss_trials)
g_mean, g_std = compute_stats(ga_trials)


def main():
    m_mean, m_std = compute_stats(manual_trials)
    c_mean, c_std = compute_stats(cvss_trials)
    g_mean, g_std = compute_stats(ga_trials)

    plt.style.use('seaborn-v0_8-whitegrid')
    fig, ax = plt.subplots(figsize=(11, 6))

    colors = {
        "Manual": "#4C72B0",
        "CVSS": "#DD8452",
        "GA": "#55A868"
    }

    # Plot mean lines
    datasets = {
        "Manual": (m_mean, m_std),
        "CVSS": (c_mean, c_std),
        "GA": (g_mean, g_std)
    }

    for label, (mean, std) in datasets.items():
        ax.plot(time_grid, mean, label=label,
                color=colors[label], linewidth=2.5)

        ax.fill_between(
            time_grid,
            mean - std,
            mean + std,
            color=colors[label],
            alpha=0.2
        )

    # Cutoff line
    ax.axvline(x=30, color='red', linestyle='--',
               alpha=0.5, label='30-min cutoff')

    # Labels
    ax.set_xlabel('Elapsed Time (minutes)')
    ax.set_ylabel('Cumulative Critical Assets Compromised')
    ax.set_title('Mean Cumulative Asset Compromise')

    ax.legend()
    ax.set_xlim(0, 31)
    ax.set_ylim(0, 8)

    plt.tight_layout()
    plt.savefig('multi_trial_comparison.png', dpi=300)
    plt.show()


if __name__ == "__main__":
    main()
