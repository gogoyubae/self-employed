<template>
  <InfoPlazaHeader />
  <div class="container mw-screen-xl">
    <button @click="goBack" class="btn ms-3">뒤로가기</button>
    <div class="card m-3">
      <div class="row g-0">
        <div class="col-md-4">
          <img
            src="@/assets/img/media/img-1.jpg"
            class="img-fluid rounded-start m-3"
            alt="..."
          />
        </div>
        <div class="col-md-8">
          <div class="card-body m-3">
            <h6 class="card-title mb-2">카테고리 > 클릭 가능하도록??</h6>
            <h3 class="card-title mb-0">
              [카페창업] 다같이 자영업!! 영상 제목입니다 #영상 #제목
            </h3>

            <p class="card-text mt-2 me-5" style="max-width: 90%">
              한줄 소개입니다. 영상을 한줄으로 소개합니다. 딱히 한줄은 아니어도
              됩니다. 자세한 소개는 아래에 있습니다. 이 영상만 있으면 나도
              카페왕!!! 카페 메뉴 추천 - 콜드브루라떼에 오트유로변경
            </p>
            <p class="card-text">
              <small class="text-body-secondary">1시간 30분</small>
            </p>
          </div>
        </div>
      </div>
    </div>
    <div class="introduce">
      <h3 class="ms-5 mb-2 mt-10" style="font-weight: 600">영상 세부사항</h3>
      <hr />
      <h4 class="ms-5 mb-2 mt-4">학습 목표</h4>
      <p class="ms-5 mt-3 mb-2" style="width: 75%">
        영상 목표입니다. 🐦모동숲 비둘기 둥지 카페 구경가기 및 매출 급상승 전략
      </p>
      <h4 class="ms-5 mb-2 mt-4">상세 소개</h4>
      <p class="ms-5 mt-3 mb-2" style="width: 75%">
        영상 설명입니다. 안녕하세요 peanut asmr입니다. 모두 잘 지내고 계신가요?
        저는 알고리즘 덕분에 구독자분들이 늘어서 얼떨떨하면서 기쁜 요즘이에요.
        바쁜 일상과 아이디어 고갈 이슈💬로 업로드가 조금 늦어졌습니다.ㅠ 이번
        영상은 모동숲 마을 사무소🏡인데요, 폴폴 날리는 먼지들과 빗소리를
        추가해서 포근함을 더해보았어요. 편안히 즐겨주기를 바라며, 앞으로 더 힐링
        되는 콘텐츠 굽굽🍞..! 해서 올게요. 감사합니다! 🐦모동숲 비둘기 둥지 카페
        구경가기 • ASMR 모동숲 갑돌패밀리 티타임🐢☕️ | ⚠️ 금일 보트 투어 쉽
      </p>
    </div>
    <hr />
    <!-- Nav pills -->
    <ul class="nav nav-pills ms-5">
      <li class="nav-item">
        <a href="#" class="nav-link active">Active</a>
      </li>
      <li class="nav-item">
        <a href="#" class="nav-link">Link</a>
      </li>
      <li class="nav-item">
        <a href="#" class="nav-link">Link</a>
      </li>
      <li class="nav-item">
        <a href="#" class="nav-link disabled" tabindex="-1" aria-disabled="true"
          >Disabled</a
        >
      </li>
    </ul>
  </div>
</template>

<script setup>
import { useRouter } from "vue-router"; // Import the router
import InfoPlazaHeader from "@/components/infoplaza/InfoPlazaHeader.vue";

// Function to toggle checkboxes
function toggleAll(source) {
  const checkboxes = document.querySelectorAll(
    ".form-check-input:not(#cycleCheckAll)"
  );
  checkboxes.forEach((checkbox) => {
    checkbox.checked = source.checked;
  });
}

// Function for navigating back
const router = useRouter();
function goBack() {
  router.go(-1); // Navigate to the previous page
}
</script>

<style>
.form-horizontal {
  margin: 20px;
}
.cards {
  margin: 60px 0px;
}
.container {
  padding: 0px 80px 0px 80px;
}
.col-form-label {
  font-weight: 500;
}
</style>
