from setuptools import setup, find_packages

setup(
    name="network_anomaly_detector",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "numpy",
        "pandas",
        "scikit-learn",
        "joblib",
	"scapy"
    ],
    entry_points={
        "console_scripts": [
            "train-anomaly-model=network_anomaly_detector.model_trainer:main"
        ,
            "scan-live-traffic=network_anomaly_detector.predict_live:main"
        ]
    },
    author="Salman",
    description="A pip-installable app to detect network traffic anomalies using a pretrained ML model.",
)
