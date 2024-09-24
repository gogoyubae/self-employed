<template>
  <div>
    <InfoPlazaHeader />
    <div class="container mw-screen-xl">
      <h2>검색 옵션</h2>
      <form class="form-horizontal">
        <div class="row mb-3">
          <!-- 사업주기별 -->
          <label for="inputEmail3" class="col-2 col-form-label"
            >사업주기별</label
          >
          <div class="col-9">
            <div class="mt-2">
              <div class="form-check form-check-inline">
                <input
                  type="checkbox"
                  class="form-check-input"
                  id="cycleCheck1"
                />
                <label class="form-check-label" for="cycleCheck1">전체</label>
              </div>
              <div class="form-check form-check-inline">
                <input
                  type="checkbox"
                  class="form-check-input"
                  id="cycleCheck2"
                />
                <label class="form-check-label" for="cycleCheck2">창업</label>
              </div>
              <div class="form-check form-check-inline">
                <input
                  type="checkbox"
                  class="form-check-input"
                  id="cycleCheck3"
                />
                <label class="form-check-label" for="cycleCheck3">성장</label>
              </div>
              <div class="form-check form-check-inline">
                <input
                  type="checkbox"
                  class="form-check-input"
                  id="cycleCheck4"
                />
                <label class="form-check-label" for="cycleCheck4"
                  >폐업, 재기</label
                >
              </div>
            </div>
          </div>

          <!-- 업종별 -->
          <label for="inputEmail3" class="col-2 col-form-label">업종별</label>
          <div class="col-9">
            <div class="mt-2">
              <div class="form-check form-check-inline">
                <input
                  type="checkbox"
                  class="form-check-input"
                  id="industryCheck1"
                />
                <label class="form-check-label" for="industryCheck1"
                  >전체</label
                >
              </div>
              <div class="form-check form-check-inline">
                <input
                  type="checkbox"
                  class="form-check-input"
                  id="industryCheck2"
                />
                <label class="form-check-label" for="industryCheck2"
                  >업종무관</label
                >
              </div>
              <div class="form-check form-check-inline">
                <input
                  type="checkbox"
                  class="form-check-input"
                  id="industryCheck3"
                />
                <label class="form-check-label" for="industryCheck3"
                  >제조업</label
                >
              </div>
              <div class="form-check form-check-inline">
                <input
                  type="checkbox"
                  class="form-check-input"
                  id="industryCheck4"
                />
                <label class="form-check-label" for="industryCheck4"
                  >도소매업</label
                >
              </div>
              <div class="form-check form-check-inline">
                <input
                  type="checkbox"
                  class="form-check-input"
                  id="industryCheck5"
                />
                <label class="form-check-label" for="industryCheck5"
                  >음식점업</label
                >
              </div>
              <div class="form-check form-check-inline">
                <input
                  type="checkbox"
                  class="form-check-input"
                  id="industryCheck6"
                />
                <label class="form-check-label" for="industryCheck6"
                  >서비스업</label
                >
              </div>
              <div class="form-check form-check-inline">
                <input
                  type="checkbox"
                  class="form-check-input"
                  id="industryCheck7"
                />
                <label class="form-check-label" for="industryCheck7"
                  >숙박업</label
                >
              </div>
            </div>
          </div>

          <!-- 과목별 -->
          <label for="inputEmail3" class="col-2 col-form-label">과목별</label>
          <div class="col-9">
            <div class="mt-2">
              <div class="form-check form-check-inline">
                <input
                  type="checkbox"
                  class="form-check-input"
                  id="subjectCheck1"
                />
                <label class="form-check-label" for="subjectCheck1">전체</label>
              </div>
              <div class="form-check form-check-inline">
                <input
                  type="checkbox"
                  class="form-check-input"
                  id="subjectCheck2"
                />
                <label class="form-check-label" for="subjectCheck2"
                  >마케팅</label
                >
              </div>
              <div class="form-check form-check-inline">
                <input
                  type="checkbox"
                  class="form-check-input"
                  id="subjectCheck3"
                />
                <label class="form-check-label" for="subjectCheck3"
                  >사업장 운영</label
                >
              </div>
              <div class="form-check form-check-inline">
                <input
                  type="checkbox"
                  class="form-check-input"
                  id="subjectCheck4"
                />
                <label class="form-check-label" for="subjectCheck4"
                  >노무&세무&법</label
                >
              </div>
              <div class="form-check form-check-inline">
                <input
                  type="checkbox"
                  class="form-check-input"
                  id="subjectCheck5"
                />
                <label class="form-check-label" for="subjectCheck5"
                  >수출입</label
                >
              </div>
              <div class="form-check form-check-inline">
                <input
                  type="checkbox"
                  class="form-check-input"
                  id="subjectCheck6"
                />
                <label class="form-check-label" for="subjectCheck6"
                  >지원사업</label
                >
              </div>
              <div class="form-check form-check-inline">
                <input
                  type="checkbox"
                  class="form-check-input"
                  id="subjectCheck7"
                />
                <label class="form-check-label" for="subjectCheck7"
                  >기업가정신</label
                >
              </div>
              <div class="form-check form-check-inline">
                <input
                  type="checkbox"
                  class="form-check-input"
                  id="subjectCheck8"
                />
                <label class="form-check-label" for="subjectCheck8">교양</label>
              </div>
            </div>
          </div>
          <label for="inputEmail3" class="col-2 col-form-label"
            >키워드 검색</label
          >

          <div class="col-9">
            <div class="mt-2">
              <form class="form-group">
                <div class="input-group input-group-sm">
                  <div class="btn-group dropdown">
                    <select
                      class="form-select"
                      aria-label="Default select example"
                    >
                      <option selected>전체</option>
                      <option value="1">과정명</option>
                      <option value="2">내용</option>
                      <option value="3">해시태그</option>
                      <option value="3">강사명</option>
                    </select>
                  </div>
                  <input
                    type="text"
                    class="form-control ms-3"
                    placeholder="Search query..."
                  />
                </div>
              </form>
            </div>
          </div>
        </div>

        <div class="justify-content-end row">
          <div class="col-9">
            <button type="submit" class="btn btn-info">검색하기</button>
          </div>
        </div>
      </form>
      <div class="cards">
        <!-- Row to contain 4 cards in a single row -->
        <div class="row">
          <div class="col-3">
            <div class="card">
              <img
                src="@/assets/img/people/img-12.jpg"
                class="card-img-top"
                alt="Card image"
              />
              <div class="card-body">
                <h5 class="card-title">Card title 1</h5>
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
            <div class="card" style="cursor: pointer">
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
  </div>
</template>

<script setup>
import InfoPlazaHeader from "@/components/infoplaza/InfoPlazaHeader.vue";
function toggleAll(source) {
  const checkboxes = document.querySelectorAll(
    ".form-check-input:not(#cycleCheckAll)"
  );
  checkboxes.forEach((checkbox) => {
    checkbox.checked = source.checked;
  });
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
