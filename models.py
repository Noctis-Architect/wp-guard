from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json

db = SQLAlchemy()


class AppSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data_json = db.Column(db.Text, nullable=False, default="{}")


class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    version = db.Column(db.String(50), default="Unknown")
    data_json = db.Column(db.Text, nullable=False) # Stores the full scan results

    def to_dict(self):
        data = json.loads(self.data_json)
        return {
            "id": self.id,
            "url": self.url,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "version": self.version,
            "results": data
        }
