import streamlit as st
import pandas as pd
import numpy as np

# Page config
st.set_page_config(
    page_title="My Streamlit App",
    page_icon="🚀",
    layout="wide"
)

# Header
st.title("🚀 My Simple Streamlit App")
st.markdown("Welcome to your first Streamlit application!")

st.divider()

# Sidebar
st.sidebar.header("⚙️ Controls")
num_points = st.sidebar.slider("Number of data points", 10, 200, 50)
chart_type = st.sidebar.selectbox("Chart Type", ["Line Chart", "Bar Chart", "Area Chart"])

# Main content
col1, col2, col3 = st.columns(3)

with col1:
    st.metric(label="Total Points", value=num_points, delta="+5")

with col2:
    st.metric(label="Average", value=f"{np.random.randint(40, 80)}", delta="-2")

with col3:
    st.metric(label="Max Value", value=f"{np.random.randint(80, 100)}", delta="+10")

st.divider()

# Generate random data
data = pd.DataFrame(
    np.random.randn(num_points, 3),
    columns=["Series A", "Series B", "Series C"]
)

st.subheader(f"📊 {chart_type}")

if chart_type == "Line Chart":
    st.line_chart(data)
elif chart_type == "Bar Chart":
    st.bar_chart(data)
else:
    st.area_chart(data)

st.divider()

# Interactive input
st.subheader("💬 Say Hello!")
name = st.text_input("Enter your name", placeholder="e.g. John")
if name:
    st.success(f"Hello, **{name}**! 👋 Welcome to Streamlit!")

# Data table
with st.expander("📋 View Raw Data"):
    st.dataframe(data, use_container_width=True)

st.caption("Built with ❤️ using Streamlit")
