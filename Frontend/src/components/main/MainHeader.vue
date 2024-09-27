<template>
  <div>
    <img src="../../assets/img/main/Main - HEADER.png" alt="" />
    <a href="/simul">
      <img
        src="../../assets/img/main/STARTBTN.png"
        alt=""
        class="main-overlay"
      />
    </a>
  </div>
</template>

<style>
.main-overlay {
  position: absolute; /* 절대 위치 설정 */
  top: 52%; /* user-info의 하단에 위치 */
  left: 50%; /* 가운데 정렬을 위해 left를 50%로 설정 */
  transform: translateX(-50%); /* 가운데 정렬 조정 */
  width: 13%; /* 너비를 60%로 설정하여 양쪽 20% 여백을 만듭니다 */
  background-color: rgba(255, 255, 255); /* 흰색 반투명 배경 */
  border-radius: 50px; /* 모서리 둥글게 */
  z-index: 1; /* 이미지 아래에 위치하도록 설정 */
  box-sizing: border-box; /* 패딩을 포함하여 전체 너비를 계산 */
}
</style>
