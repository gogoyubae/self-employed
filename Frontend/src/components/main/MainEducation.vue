<template>
  <div>
    <div class="row">
      <div class="cards">
        <h3 class="mb-5" style="font-weight: 600">교육정보</h3>
        <!-- Row to contain 4 cards in a single row -->
        <div class="row">
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

                <div class="d-flex align-items-center">
                  <a href="#" class="btn btn-sm btn-primary mt-2">시청하기</a>
                  <router-link
                    to="/infoplaza/education/video"
                    href="#"
                    class="btn btn-sm btn-primary mt-2 ms-2"
                    >상세보기</router-link
                  >
                </div>
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

                <div class="d-flex align-items-center">
                  <a href="#" class="btn btn-sm btn-primary mt-2">시청하기</a>
                  <router-link
                    to="/infoplaza/education/video"
                    href="#"
                    class="btn btn-sm btn-primary mt-2 ms-2"
                    >상세보기</router-link
                  >
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
</script>

<style scoped>
</style>
