import numpy as np
import csv
from scipy.optimize import least_squares
from scipy.ndimage import gaussian_filter
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

# The text still has a slight tilt. Let me measure it from the text endpoints
# and apply additional rotation to make it horizontal.
# From the images, text goes from lower-left to upper-right with a slight angle.
# Let me estimate: the text spans roughly u=[-0.055, 0.065], v=[-0.025, 0.01]
# That's du=0.12, dv=0.035, angle = atan2(0.035, 0.12) ≈ 16 degrees
# Let me try rotating by about -16 degrees more

extra_angle = np.arctan2(0.035, 0.12)
print(f"Extra rotation: {np.degrees(extra_angle):.1f} degrees")

cos_e = np.cos(-extra_angle)
sin_e = np.sin(-extra_angle)
final_u = rot_u * cos_e - rot_v * sin_e
final_v = rot_u * sin_e + rot_v * cos_e

# Rasterize with higher resolution
res_x, res_y = 4000, 800
u_min, u_max = -0.08, 0.09
v_min, v_max = -0.02, 0.02

grid = np.zeros((res_y, res_x))
for i in range(len(final_u)):
    ui = int((final_u[i] - u_min) / (u_max - u_min) * res_x)
    vi = int((final_v[i] - v_min) / (v_max - v_min) * res_y)
    if 0 <= ui < res_x and 0 <= vi < res_y:
        grid[vi, ui] += 1

grid_smooth = gaussian_filter(grid, sigma=4)

# White on black - best contrast
fig, ax = plt.subplots(figsize=(40, 6))
ax.imshow(grid_smooth, origin='lower', cmap='gray', aspect='auto',
          extent=[u_min, u_max, v_min, v_max])
ax.set_title('Final - tilt corrected, smoothed')
plt.tight_layout()
plt.savefig('final_text.png', dpi=250)
plt.close()

# Also scatter plot version
fig, ax = plt.subplots(figsize=(40, 8))
mask = (final_v > -0.02) & (final_v < 0.02)
ax.scatter(final_u[mask], final_v[mask], s=2, alpha=0.8, c='white', marker='.', edgecolors='none')
ax.set_facecolor('black')
ax.set_aspect('equal')
ax.set_xlim(-0.07, 0.08)
ax.set_ylim(-0.015, 0.015)
plt.tight_layout()
plt.savefig('final_scatter.png', dpi=250)
plt.close()

print("Done")
