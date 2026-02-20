Planetarium: Star Tracker Calibration

You are given star-centroid measurements from a small star-tracker camera.

Files:
  - tracker_dump.csv

Columns:
  - x_px, y_px : centroid pixel coordinates (0..1023)
  - flux       : brightness proxy
  - name       : non-empty only for a handful of guide stars
  - ra_h       : right ascension in hours (only for named guide stars)
  - dec_deg    : declination in degrees (only for named guide stars)
  - ts         : timestamp (not required)

Goal:
  Recover the hidden message that appears when the field is calibrated back to the tangent plane.

Notes:
  - RA wraps: 0h == 24h (be careful computing ΔRA).
  - A tangent-plane (gnomonic) model is appropriate.
  - The camera has mild radial distortion.

Suggested deterministic approach:
  1) Use the named guide stars to fit a camera model (scale, rotation, translation, radial distortion).
  2) Invert the model for all stars back into tangent-plane coordinates (u,v).
  3) Use Deneb to define +X, and Altair to choose the sign of +Y (removes mirror ambiguity).
  4) Filter by flux/SNR to reduce background.
