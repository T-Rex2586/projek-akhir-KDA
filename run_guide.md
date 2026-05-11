# Panduan Menjalankan LUCID-DDoS

Proyek ini adalah framework deteksi serangan DDoS berbasis **Random Forest**. Berikut adalah langkah-langkah untuk menjalankannya:

## 1. Persiapan Lingkungan (Setup)

Pastikan Anda memiliki Python (disarankan v3.9) dan `tshark` terinstal di sistem Anda.

### Instalasi Dependensi
Jalankan perintah berikut di terminal Anda:
```bash
pip install tensorflow==2.7.1 scikit-learn h5py pyshark protobuf==3.19.6 joblib
```

> [!IMPORTANT]
> Anda harus menginstal **Wireshark/Tshark** terlebih dahulu karena `pyshark` membutuhkannya untuk membaca file `.pcap`. Unduh di [wireshark.org](https://www.wireshark.org/).

## 2. Prapemrosesan Data (Traffic Pre-processing)

Langkah ini mengubah file `.pcap` mentah menjadi format yang bisa dipahami oleh model AI.

### Langkah A: Ekstraksi Fitur
Jalankan perintah ini untuk mengekstrak fitur dari dataset sampel:
```bash
python lucid_dataset_parser.py --dataset_type DOS2019 --dataset_folder ./sample-dataset/ --packets_per_flow 10 --dataset_id DOS2019 --traffic_type all --time_window 10
```
Ini akan menghasilkan file `.data` di folder `sample-dataset`.

### Langkah B: Penggabungan dan Normalisasi
Jalankan perintah ini untuk menyiapkan dataset akhir (train/val/test):
```bash
python lucid_dataset_parser.py --preprocess_folder ./sample-dataset/
```
Ini akan menghasilkan file `.hdf5` yang siap digunakan untuk pelatihan.

## 3. Pelatihan Model (Training)

Untuk melatih model Random Forest menggunakan dataset yang sudah diproses:
```bash
python lucid_RF.py --train ./sample-dataset/ -cv 5
```
Model terbaik akan disimpan di folder `output/` dengan ekstensi `.joblib`.

## 4. Pengujian (Testing)

Setelah pelatihan selesai, Anda bisa menguji performa model:
```bash
python lucid_RF.py --predict ./sample-dataset/ --model ./output/10t-10n-DOS2019-LUCID-RF.joblib
```

## 5. Inferensi Online (Opsional)

Jika ingin mencoba mendeteksi langsung dari file `.pcap`:
```bash
python lucid_RF.py --predict_live ./sample-dataset/CIC-DDoS-2019-UDPLag.pcap --model ./output/10t-10n-DOS2019-LUCID-RF.joblib --dataset_type DOS2019
```
