<template>
  <div>
    <img
      src="@/assets/img/infoplaza/infoplaza.png"
      class="result-image mb-10"
    />
    <div class="container">
      <div class="result-text" style="color: white">정보광장</div>
      <!-- <div class="overlay">
        <div class="overlay-text">
          <div class="text-center d-flex justify-content-center">
            <div class="d-flex w-100" style="max-width: 1000px">
              <div class="flex-item">
                <RouterLink to="/infoPlaza/industry"
                  ><h4>인기 업종</h4></RouterLink
                >
              </div>
              <div class="flex-item">
                <a href="/infoPlaza/floatpopular"><h4>상권 정보</h4></a>
              </div>
              <div class="flex-item">
                <RouterLink to="/infoPlaza/education"
                  ><h4>교육 정보</h4></RouterLink
                >
              </div>
              <div class="flex-item">
                <RouterLink to="/infoPlaza/PersonalLoan"
                  ><h4>대출 정보</h4></RouterLink
                >
              </div>
              <div class="flex-item">
                <RouterLink to="/infoPlaza/news"><h4>뉴스</h4></RouterLink>
              </div>
            </div>
          </div>
        </div>
      </div> -->
    </div>
  </div>
</template>

<script setup></script>

<style>
/* Existing styles */
.result-container {
  position: relative;
}

.result-image {
  width: 100%;
  height: 300px;
  object-fit: cover;
  z-index: 1;
}

.result-text {
  position: absolute;
  top: 30%;
  left: 15%;
  transform: translate(-50%, -50%);
  color: white;
  padding: 10px;
  border-radius: 5px;
  z-index: 2;
  font-size: 30px;
  font-weight: 600;
}

.overlay {
  position: absolute;
  top: 35%;
  left: 50%;
  transform: translateX(-50%);
  width: 80%;
  background-color: rgba(255, 255, 255);
  border-radius: 40px;
  z-index: 1;
  box-sizing: border-box;
}

.overlay-text {
  color: black;
  width: 100%;
  font-size: 24px;
  margin: 2% 0;
}

.container {
  padding: 0px 80px 0px 80px;
}

.flex-item {
  flex: 1;
  text-align: center;
}

/* Dropdown styles for loan info */
.loan-info-container {
  position: relative;
}

.loan-info-title {
  cursor: pointer;
  /* Add hover or click styles if needed */
}

.loan-info-dropdown {
  display: none;
  position: absolute;
  top: 100%;
  left: 0;
  background-color: white;
  border-radius: 5px;
  box-shadow: 0px 4px 8px rgba(0, 0, 0, 0.1);
  width: 100%;
}

.loan-info-container:hover .loan-info-dropdown,
.loan-info-container:focus-within .loan-info-dropdown {
  display: block;
}

.loan-info-dropdown h5 {
  margin: 0;
  padding: 10px;
  cursor: pointer;
  text-align: center;
  color: black;
}

.loan-info-dropdown h5:hover {
  background-color: #f0f0f0;
}
</style>
