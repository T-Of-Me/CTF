import numpy as np
import csv
from scipy.optimize import least_squares
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

# Read CSV
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

guide_uv = []
guide_xy = []
for g in guides:
    u, v = ra_dec_to_tangent(g[4], g[5], ra0_h, dec0_deg)
    guide_uv.append((u, v))
    guide_xy.append((g[0], g[1]))

guide_uv = np.array(guide_uv)
guide_xy = np.array(guide_xy)

def pixel_to_tangent(x, y, params):
    cx, cy, k1, a, b, c, d = params
    dx = x - cx
    dy = y - cy
    r2 = dx**2 + dy**2
    scale = 512**2
    r2n = r2 / scale
    factor = 1 + k1 * r2n
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

# Transform all detections
all_u = []
all_v = []
all_flux = []
for r in rows:
    u, v = pixel_to_tangent(r[0], r[1], params)
    all_u.append(u)
    all_v.append(v)
    all_flux.append(r[2])

all_u = np.array(all_u)
all_v = np.array(all_v)
all_flux = np.array(all_flux)

# Rotate so Deneb defines +X
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

# Multiple views to read the text
for flip_x in [False, True]:
    for flip_y in [False, True]:
        fig, ax = plt.subplots(figsize=(20, 12))
        xu = -rot_u if flip_x else rot_u
        yv = -rot_v if flip_y else rot_v
        ax.scatter(xu, yv, s=1.5, alpha=0.6, c='black')
        ax.set_aspect('equal')
        ax.set_title(f'flip_x={flip_x}, flip_y={flip_y}')
        plt.tight_layout()
        plt.savefig(f'view_fx{int(flip_x)}_fy{int(flip_y)}.png', dpi=200)
        plt.close()

print("Saved all views")

# High-res view with best flux filtering
fig, ax = plt.subplots(figsize=(24, 14))
# Don't flip anything, just plot as-is
ax.scatter(rot_u, rot_v, s=2, alpha=0.7, c='black')
ax.set_aspect('equal')
ax.set_title('No flip')
plt.tight_layout()
plt.savefig('view_nofliip_hires.png', dpi=250)
plt.close()
print("Done")
