<template>
  <div class="">
    <div class="title">교육 정보</div>
    <div class="con-card">
      <!-- Row to contain 4 cards in a single row -->
      <div class="row">
        <div class="col-3">
          <div class="card">
            <img :src="card.imgSrc" class="card-img-top" :alt="card.imgAlt" />
            <div class="card-body">
              <h5 class="card-title">{{ card.title }}</h5>
              <p class="card-text fs-sm p-5">
                {{ card.text }}
              </p>
              <a :href="card.link" class="btn btn-sm btn-primary"
                >Go somewhere</a
              >
            </div>
          </div>
        </div>

        <div class="col-3">
          <div class="card">
            <img
              src="@/assets/img/people/img-12.jpg"
              class="card-img-top"
              alt="Card image"
            />
            <div class="card-body">
              <h5 class="card-title">Card title 2</h5>
              <p class="card-text fs-sm">
                Some quick example text to build on the card title and make up
                the bulk of the card's content.
              </p>
              <a href="#" class="btn btn-sm btn-primary">Go somewhere</a>
            </div>
          </div>
        </div>

        <div class="col-3">
          <div class="card">
            <img
              src="@/assets/img/people/img-12.jpg"
              class="card-img-top"
              alt="Card image"
            />
            <div class="card-body">
              <h5 class="card-title">Card title 3</h5>
              <p class="card-text fs-sm">
                Some quick example text to build on the card title and make up
                the bulk of the card's content.
              </p>
              <a href="#" class="btn btn-sm btn-primary">Go somewhere</a>
            </div>
          </div>
        </div>

        <div class="col-3">
          <div class="card">
            <img
              src="@/assets/img/people/img-12.jpg"
              class="card-img-top"
              alt="Card image"
            />
            <div class="card-body">
              <h5 class="card-title">Card title 4</h5>
              <p class="card-text fs-sm">
                Some quick example text to build on the card title and make up
                the bulk of the card's content.
              </p>
              <a href="#" class="btn btn-sm btn-primary">Go somewhere</a>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import imgSrc from '@/assets/img/people/img-12.jpg'; // 이미지 파일을 import

export default {
  data() {
    return {
      card: {
        title: '여기 적힌 글은',
        text: 'script에서 때려넣은 글임',
        imgSrc: imgSrc, // import한 이미지를 사용
        imgAlt: 'Card image',
        link: '#',
      },
    };
  },
};
</script>

<style>
.container {
  padding: 0px 80px;
}

.title {
  padding: 5px 0px;
}
</style>
