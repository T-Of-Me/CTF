import numpy as np
import csv
from scipy.optimize import least_squares
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

rows = []
guides = []
with open('tracker_dump.csv', 'r') as f:
    reader = csv.DictReader(f)
    for r in reader:
        x = float(r['x_px'])
        y = float(r['y_px'])
        flux = float(r['flux'])
        name = r['name'].strip() if r['name'] else ''
        ra_h = float(r['ra_h']) if r['ra_h'] else None
        dec_deg = float(r['dec_deg']) if r['dec_deg'] else None
        rows.append((x, y, flux, name, ra_h, dec_deg))
        if name:
            guides.append((x, y, flux, name, ra_h, dec_deg))

ra0_h = 23.92
dec0_deg = 22.0

def ra_dec_to_tangent(ra_h, dec_deg, ra0_h, dec0_deg):
    ra = ra_h * 15 * np.pi / 180
    dec = dec_deg * np.pi / 180
    ra0 = ra0_h * 15 * np.pi / 180
    dec0 = dec0_deg * np.pi / 180
    cos_c = (np.sin(dec0)*np.sin(dec) + np.cos(dec0)*np.cos(dec)*np.cos(ra - ra0))
    u = np.cos(dec) * np.sin(ra - ra0) / cos_c
    v = (np.cos(dec0)*np.sin(dec) - np.sin(dec0)*np.cos(dec)*np.cos(ra - ra0)) / cos_c
    return u, v

guide_uv = np.array([ra_dec_to_tangent(g[4], g[5], ra0_h, dec0_deg) for g in guides])
guide_xy = np.array([(g[0], g[1]) for g in guides])

def pixel_to_tangent(x, y, params):
    cx, cy, k1, a, b, c, d = params
    dx = x - cx
    dy = y - cy
    r2 = (dx**2 + dy**2) / 512**2
    factor = 1 + k1 * r2
    dx2 = dx * factor
    dy2 = dy * factor
    u = a * dx2 + b * dy2
    v = c * dx2 + d * dy2
    return u, v

def residuals(params):
    res = []
    for i in range(len(guide_xy)):
        u_pred, v_pred = pixel_to_tangent(guide_xy[i, 0], guide_xy[i, 1], params)
        res.append(u_pred - guide_uv[i, 0])
        res.append(v_pred - guide_uv[i, 1])
    return res

u_range = guide_uv[:, 0].max() - guide_uv[:, 0].min()
x_range = guide_xy[:, 0].max() - guide_xy[:, 0].min()
scale_est = u_range / x_range
p0 = [512, 512, 0.0, scale_est, 0, 0, scale_est]
result = least_squares(residuals, p0, method='lm')
params = result.x

all_uv = np.array([pixel_to_tangent(r[0], r[1], params) for r in rows])
all_u = all_uv[:, 0]
all_v = all_uv[:, 1]
all_flux = np.array([r[2] for r in rows])

deneb_idx = next(i for i, g in enumerate(guides) if g[3] == 'Deneb')
altair_idx = next(i for i, g in enumerate(guides) if g[3] == 'Altair')
deneb_u, deneb_v = pixel_to_tangent(guides[deneb_idx][0], guides[deneb_idx][1], params)
altair_u, altair_v = pixel_to_tangent(guides[altair_idx][0], guides[altair_idx][1], params)

angle_deneb = np.arctan2(deneb_v, deneb_u)
cos_a = np.cos(-angle_deneb)
sin_a = np.sin(-angle_deneb)
rot_u = all_u * cos_a - all_v * sin_a
rot_v = all_u * sin_a + all_v * cos_a

altair_rot_v = altair_u * sin_a + altair_v * cos_a
if altair_rot_v < 0:
    rot_v = -rot_v

# Rasterize to a high-res binary image
# The text seems to be formed by denser regions (the letter strokes)
res_x, res_y = 3000, 1500
u_min, u_max = -0.07, 0.08
v_min, v_max = -0.045, 0.025

grid = np.zeros((res_y, res_x))
for i in range(len(rot_u)):
    ui = int((rot_u[i] - u_min) / (u_max - u_min) * res_x)
    vi = int((rot_v[i] - v_min) / (v_max - v_min) * res_y)
    if 0 <= ui < res_x and 0 <= vi < res_y:
        grid[vi, ui] += 1

# Apply gaussian blur for better readability
from scipy.ndimage import gaussian_filter
grid_smooth = gaussian_filter(grid, sigma=3)

# White text on black background
fig, ax = plt.subplots(figsize=(30, 10))
ax.imshow(grid_smooth, origin='lower', cmap='gray', aspect='auto',
          extent=[u_min, u_max, v_min, v_max])
ax.set_title('Smoothed density (white=dense=text)')
plt.tight_layout()
plt.savefig('text_white_on_black.png', dpi=200)
plt.close()

# Black text on white background
fig, ax = plt.subplots(figsize=(30, 10))
ax.imshow(grid_smooth, origin='lower', cmap='gray_r', aspect='auto',
          extent=[u_min, u_max, v_min, v_max])
ax.set_title('Smoothed density inverted (black=dense=text)')
plt.tight_layout()
plt.savefig('text_black_on_white.png', dpi=200)
plt.close()

# Also try: separate the "text" stars from "background" stars
# The text stars might have a different flux distribution
# Let's check: what flux do stars in the text region have vs background?
text_mask = (rot_v > -0.035) & (rot_v < 0.015) & (rot_u > -0.06) & (rot_u < 0.07)
bg_mask = ~text_mask & (np.sqrt(rot_u**2 + rot_v**2) < 0.065)

print(f"Text region stars: {text_mask.sum()}")
print(f"Background stars: {bg_mask.sum()}")
print(f"Text region flux: mean={all_flux[text_mask].mean():.1f}, median={np.median(all_flux[text_mask]):.1f}")
print(f"Background flux: mean={all_flux[bg_mask].mean():.1f}, median={np.median(all_flux[bg_mask]):.1f}")

# Flux histogram
print("\nFlux percentiles (all):")
for p in [10, 25, 50, 75, 90, 95]:
    print(f"  {p}%: {np.percentile(all_flux, p):.1f}")

print("Done")
