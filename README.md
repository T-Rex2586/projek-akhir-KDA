# LUCID-DDoS: Solusi Ringan Deteksi Serangan DDoS
#
LUCID-DDoS adalah framework deteksi serangan DDoS berbasis Machine Learning yang dirancang untuk efisiensi tinggi pada lingkungan dengan sumber daya terbatas. Proyek ini mengintegrasikan mekanisme prapemrosesan trafik yang cerdas dengan algoritme **Random Forest** untuk memberikan hasil deteksi yang cepat dan akurat.

---

##  Fitur Utama
- **Efisiensi Tinggi**: Performa optimal pada perangkat hardware spesifikasi rendah (Edge devices).
- **Fleksibel**: Mendukung dataset DDoS standar industri seperti CIC-IDS2017, CSE-CIC-IDS2018, dan CIC-DDoS2019.
- **Deteksi Real-time**: Waktu inferensi milidetik untuk respon serangan yang lebih cepat.
- **Prapemrosesan Otomatis**: Konversi trafik PCAP mentah menjadi fitur siap-latih secara otomatis.

##  Persyaratan Sistem
- **Python**: v3.9 (Direkomendasikan)
- **Tshark**: Bagian dari Wireshark (Wajib terinstal untuk parsing PCAP)
- **Library**: `tensorflow`, `scikit-learn`, `pyshark`, `h5py`, `joblib`, `numpy`

##  Panduan Penggunaan

### 1. Prapemrosesan Data
Ubah file trafik mentah (`.pcap`) menjadi dataset fitur:
```bash
# Tahap 1: Ekstraksi fitur dari PCAP
python -m src.lucid_dataset_parser --dataset_type DOS2019 --dataset_folder ./data/raw/ --output_folder ./data/processed/ --packets_per_flow 10 --dataset_id DOS2019 --traffic_type all --time_window 10

# Tahap 2: Finalisasi dan normalisasi dataset
python -m src.lucid_dataset_parser --preprocess_folder ./data/processed/
```

### 2. Pelatihan Model
Latih model Random Forest menggunakan dataset yang telah diproses:
```bash
python -m src.lucid_RF --train ./data/processed/ -cv 5
```
Model terbaik akan disimpan otomatis di folder `output/` dalam format `.joblib`.

### 3. Evaluasi & Inferensi
**Uji model pada test set:**
```bash
python -m src.lucid_RF --predict ./data/processed/ --model ./output/10t-10n-DOS2019-LUCID-RF.joblib
```

**Inferensi langsung pada file PCAP:**
```bash
python -m src.lucid_RF --predict_live ./data/raw/CIC-DDoS-2019-UDPLag.pcap --model ./output/10t-10n-DOS2019-LUCID-RF.joblib --dataset_type DOS2019
```

---

##  Lisensi
Proyek ini dilisensikan di bawah **Apache License, Version 2.0**.

## Referensi Ilmiah
Jika Anda menggunakan proyek ini dalam riset Anda, silakan kutip referensi berikut:

1. **LUCID Original Paper**:
   > R. Doriguzzi-Corin, S. Millar, S. Scott-Hayward, J. Martínez-del-Rincón and D. Siracusa, *"Lucid: A Practical, Lightweight Deep Learning Solution for DDoS Attack Detection,"* in IEEE Transactions on Network and Service Management, vol. 17, no. 2, pp. 876-889, June 2020, doi: 10.1109/TNSM.2020.2971776.

2. **SDN-based Detection Reference**:
   > H. Nurwarsito and M. F. Nadhif, *"DDoS Attack Early Detection and Mitigation System on SDN using Random Forest Algorithm and Ryu Framework,"* in 2021 8th International Conference on Computer and Communication Engineering (ICCCE), 2021, pp. 178-183, doi: 10.1109/ICCCE50029.2021.9467167.