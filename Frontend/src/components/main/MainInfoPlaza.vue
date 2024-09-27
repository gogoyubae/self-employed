<template>
<div class="container mb-5">
    <h2 class="fw-bold mb-5">정보광장</h2>
        <div class="content-wrapper  mb-10">
            <div class="adjusted-float-popular">
                <div class="custom-map-container">
                <FloatPopularContent :showLocationInfo="false" />
            </div>
            </div>
            <div class="adjusted-main-popular">
                <MainPopularIndustry class=""/>
            </div>
        </div>

    <div class="row">
        <div class="col-6">
            <MainEducation/>
        </div>
        <div class="col-6">
            <MainLoan/>
        </div>
    </div>
</div>
</template>

<script setup>
import FloatPopularContent from '@/components/infoplaza/FloatPopularContent.vue';
import MainEducation from '@/components/main/MainEducation.vue';
import MainLoan from '@/components/main/MainLoan.vue';
import MainPopularIndustry from '@/components/main/MainPopularIndustry.vue';
</script>

<style>
.content-wrapper {
display: flex;
justify-content: space-between;
}

.adjusted-float-popular {
flex: 2; /* 필요한 크기로 조정 */
}

.adjusted-main-popular {
flex: 1; /* 필요한 크기로 조정 */
}

.custom-map-container {
    height: 50vh; /* 원하는 높이로 조정 */
    overflow: hidden;
}

/* col-1, col-6에 대한 스타일 재정의 */
.adjusted-float-popular .col-1 {
flex: 0 0 20%; /* col-1을 20%로 설정 */
max-width: 10%;
position: relative;
left: -3%; /* 왼쪽으로 5% 이동 */
padding: 0px 0px 0px 0px;
}

.adjusted-float-popular .col-6 {
left: -5%;
flex: 0 0 75%;
}

</style>
