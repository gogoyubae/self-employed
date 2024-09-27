<template>
  <div>
    <div class="d-flex align-items-center justify-content-between mb-5">
      <h3>교육정보</h3>
        <router-link
        to="/infoplaza/education"
        class="text-primary fw-bold"
      >
        더보기 &gt;
      </router-link>
      </div>

        <div class="row">

        <!-- Row to contain 4 cards in a single row -->
          <div class="col-6">
            <div class="card" style="cursor: pointer">
              <img
                src="@/assets/img/media/img-1.jpg"
                class="card-img-top"
                alt="Card image"
              />
              <div class="card-body">
                <h5 class="card-title">
                  [카페창업] 다같이 자영업!! 영상 제목입니다 #영상 #제목
                </h5>

              </div>
            </div>
          </div>
          <div class="col-6">
            <div class="card" style="cursor: pointer">
              <img
                src="@/assets/img/media/img-1.jpg"
                class="card-img-top"
                alt="Card image"
              />
              <div class="card-body">
                <h5 class="card-title">
                  [카페창업] 다같이 자영업!! 영상 제목입니다 #영상 #제목
                </h5>

              </div>
            </div>
          </div>
        </div>
  </div>
</template>

<script setup>
</script>

<style scoped>
.card-img-top {
  height: 100px; /* 원하는 높이로 조정 */
  object-fit: cover; /* 이미지 비율 유지하면서 잘리도록 설정 */
}
</style>
