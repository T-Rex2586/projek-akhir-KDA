# Copyright (c) 2024 - DDoS Detection Project
# Data Preprocessing Module for Random Forest DDoS Detection
#
# This module handles:
# 1. Loading raw flow data
# 2. Handling missing values
# 3. Removing duplicates
# 4. Normalization/Standardization
# 5. Feature-label splitting
# 6. Train/test splitting

import sys
import os
import numpy as np
import argparse

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.util_functions import load_dataset, SEED
from sklearn.utils import shuffle
from sklearn.model_selection import train_test_split
import glob
import h5py


def preprocess_dataset(dataset_folder, test_size=0.2, random_state=SEED):
    """
    Preprocess the dataset for Random Forest training.

    Steps:
    1. Load train and validation HDF5 datasets
    2. Reshape from 3D/4D to 2D for RF (flatten each sample)
    3. Handle missing values (NaN -> 0)
    4. Shuffle the data
    5. Return preprocessed X, Y arrays

    Args:
        dataset_folder: Path to folder containing HDF5 files
        test_size: Fraction of data to use for testing
        random_state: Random seed for reproducibility

    Returns:
        X_train, X_val, X_test, Y_train, Y_val, Y_test
    """
    # Load training data
    train_files = glob.glob(dataset_folder + "/*-train.hdf5")
    val_files = glob.glob(dataset_folder + "/*-val.hdf5")
    test_files = glob.glob(dataset_folder + "/*-test.hdf5")

    if not train_files:
        raise FileNotFoundError(f"No training HDF5 files found in {dataset_folder}")

    X_train, Y_train = load_dataset(train_files[0])
    print(f"Loaded training set: {X_train.shape[0]} samples")

    X_val, Y_val = None, None
    if val_files:
        X_val, Y_val = load_dataset(val_files[0])
        print(f"Loaded validation set: {X_val.shape[0]} samples")

    X_test, Y_test = None, None
    if test_files:
        X_test, Y_test = load_dataset(test_files[0])
        print(f"Loaded test set: {X_test.shape[0]} samples")

    # Step 1: Flatten from 4D (samples, rows, cols, 1) to 2D (samples, features)
    X_train = X_train.reshape(X_train.shape[0], -1)
    if X_val is not None:
        X_val = X_val.reshape(X_val.shape[0], -1)
    if X_test is not None:
        X_test = X_test.reshape(X_test.shape[0], -1)

    # Step 2: Handle missing values (replace NaN with 0)
    X_train = np.nan_to_num(X_train, nan=0.0)
    if X_val is not None:
        X_val = np.nan_to_num(X_val, nan=0.0)
    if X_test is not None:
        X_test = np.nan_to_num(X_test, nan=0.0)

    # Step 3: Remove duplicate samples
    unique_indices = np.unique(X_train, axis=0, return_index=True)[1]
    original_count = X_train.shape[0]
    X_train = X_train[sorted(unique_indices)]
    Y_train = Y_train[sorted(unique_indices)]
    removed = original_count - X_train.shape[0]
    if removed > 0:
        print(f"Removed {removed} duplicate samples from training set")

    # Step 4: Shuffle the data
    X_train, Y_train = shuffle(X_train, Y_train, random_state=random_state)
    if X_val is not None:
        X_val, Y_val = shuffle(X_val, Y_val, random_state=random_state)

    # Step 5: Ensure labels are 1D
    Y_train = np.array(Y_train).ravel()
    if Y_val is not None:
        Y_val = np.array(Y_val).ravel()
    if Y_test is not None:
        Y_test = np.array(Y_test).ravel()

    # Print dataset statistics
    print("\n--- Dataset Statistics ---")
    print(f"Training:   {X_train.shape[0]} samples, {np.sum(Y_train == 1)} DDoS, {np.sum(Y_train == 0)} Normal")
    if X_val is not None:
        print(f"Validation: {X_val.shape[0]} samples, {np.sum(Y_val == 1)} DDoS, {np.sum(Y_val == 0)} Normal")
    if X_test is not None:
        print(f"Test:       {X_test.shape[0]} samples, {np.sum(Y_test == 1)} DDoS, {np.sum(Y_test == 0)} Normal")
    print(f"Features per sample: {X_train.shape[1]}")

    return X_train, X_val, X_test, Y_train, Y_val, Y_test


def main():
    parser = argparse.ArgumentParser(description='Preprocess dataset for RF DDoS detection')
    parser.add_argument('--dataset_folder', type=str, required=True,
                        help='Folder containing HDF5 dataset files')
    parser.add_argument('--test_size', type=float, default=0.2,
                        help='Fraction of data for testing (default: 0.2)')
    args = parser.parse_args()

    X_train, X_val, X_test, Y_train, Y_val, Y_test = preprocess_dataset(args.dataset_folder)
    print("\nPreprocessing complete!")


if __name__ == "__main__":
    main()
