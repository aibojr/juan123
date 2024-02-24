import streamlit as st
import pandas as pd
import numpy as np

st.header("Welcome to XOR Cipher!")
st.write("### What is your name?")

txt_FNAME = st.text_area("FIRST NAME:")
txt_LNAME = st.text_area("LAST NAME:")

btn_submit = st.button("Submit")

if btn_submit:
    st.error(f"Hello {txt_FNAME} {txt_LNAME}!")



chart_data = pd.DataFrame(np.random.randn(20, 3), columns=["a", "b", "c"])

st.scatter_chart(chart_data)