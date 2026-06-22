# Detection Engine

ARGUS uses platform-specific packet capture implementations while maintaining a common machine learning workflow.

## Components

- macos/live_detect.py
  - Uses Bettercap-based packet capture.

- windows/live_detect.py
  - Uses Npcap-based packet capture.

- train_model.py
  - Trains the machine learning models used by both platforms.

Both implementations perform the same detection pipeline and share the same trained models.
